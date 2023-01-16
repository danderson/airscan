package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/brutella/dnssd"
	"github.com/davecgh/go-spew/spew"
	"github.com/godbus/dbus/v5"
	"github.com/stapelberg/airscan"
)

func discoverInteractive(ctx context.Context, debug bool) error {
	add := func(svc dnssd.BrowseEntry) {
		if debug {
			log.Printf("DNSSD service discovered: %v", spew.Sdump(svc))
		}
		humanName := humanDeviceName(svc)
		log.Printf("device %q discovered (use -host=%q)", humanName, svc.Host)
	}
	rm := func(svc dnssd.BrowseEntry) {
		log.Printf("device %q vanished", humanDeviceName(svc))
	}
	return discoverAvahi(ctx, add, rm)
}

// discover looks for airscan-capable devices on the local network.
// add and rm are always called sequentially from a single goroutine,
// i.e. no locking is required in the callbacks.
func discover(ctx context.Context, add, rm func(dnssd.BrowseEntry)) error {
	if err := dnssd.LookupType(ctx, airscan.ServiceName, add, rm); !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}

// lookup resolves hostname using mdns.
func lookup(ctx context.Context, hostname string) (*dnssd.BrowseEntry, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var ret *dnssd.BrowseEntry
	add := func(svc dnssd.BrowseEntry) {
		if svc.Host == hostname {
			ret = &svc
			cancel()
		}
	}
	rm := func(dnssd.BrowseEntry) {}
	if err := discover(ctx, add, rm); err != nil {
		return nil, err
	}
	return ret, nil
}

type avahiScanner struct {
	ctx     context.Context
	conn    *dbus.Conn
	avahi   dbus.BusObject
	add, rm func(dnssd.BrowseEntry)

	sync.Mutex
	// resolved notes names already given to caller. The way avahi
	// works, you get separate notifications for devices over IPv4 and
	// IPv6, and have to kick off separate IP resolution requests as
	// well. This prevents duplicate notifications by only returning
	// IPs for the first address family that completes resolution.
	resolved map[string]bool
}

func discoverAvahi(ctx context.Context, add, rm func(dnssd.BrowseEntry)) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return err
	}
	avahi := conn.Object("org.freedesktop.Avahi", dbus.ObjectPath("/"))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	scan := avahiScanner{
		ctx:      ctx,
		conn:     conn,
		avahi:    avahi,
		add:      add,
		rm:       rm,
		resolved: map[string]bool{},
	}
	return scan.run()
}

func (s *avahiScanner) run() error {
	call := s.avahi.CallWithContext(s.ctx, "org.freedesktop.DBus.Peer.Ping", 0)
	if call.Err != nil {
		// Avahi not available
		return nil
	}

	sig := make(chan *dbus.Signal)
	s.conn.Signal(sig)
	defer func() {
		s.conn.RemoveSignal(sig)
	sigDrain:
		for {
			select {
			case <-sig:
			default:
				break sigDrain
			}
		}
	}()

	call = s.avahi.CallWithContext(s.ctx, "org.freedesktop.Avahi.Server.ServiceBrowserNew", 0, -1, -1, "_uscan._tcp", "local", uint(0))
	if call.Err != nil {
		return fmt.Errorf("browsing with avahi: %w", call.Err)
	}

sigLoop:
	for {
		select {
		case evt := <-sig:
			switch evt.Name {
			case "org.freedesktop.Avahi.ServiceBrowser.ItemNew":
				if err := s.resolve(s.ctx, evt.Body); err != nil {
					return err
				}
			case "org.freedesktop.Avahi.ServiceBrowser.AllForNow":
				break sigLoop
			}
		case <-s.ctx.Done():
			return nil
		}
	}

	return nil
}

func (s *avahiScanner) resolve(ctx context.Context, args []any) error {
	if l := len(args); l != 6 {
		return fmt.Errorf("wrong avahi arg length %d, want 6", l)
	}
	intf, ok := args[0].(int32)
	if !ok {
		return fmt.Errorf("wrong type %T for interface index", args[0])
	}
	proto, ok := args[1].(int32)
	if !ok {
		return fmt.Errorf("wrong type %T for IP protocol", args[1])
	}
	name, ok := args[2].(string)
	if !ok {
		return fmt.Errorf("wrong type %T for device name", args[2])
	}
	typ, ok := args[3].(string)
	if !ok {
		return fmt.Errorf("wrong type %T for service type", args[3])
	}
	if typ != "_uscan._tcp" {
		return fmt.Errorf("unexpected dns-sd type %q", typ)
	}
	domain, ok := args[4].(string)
	if !ok {
		return fmt.Errorf("wrong type %T for domain name", args[4])
	}
	s.Lock()
	alreadyResolved := s.resolved[name]
	s.Unlock()
	if alreadyResolved {
		return nil
	}

	call := s.avahi.CallWithContext(ctx, "org.freedesktop.Avahi.Server.ResolveService", 0, intf, proto, name, typ, domain, proto, uint32(0))
	if call.Err != nil {
		return fmt.Errorf("resolving %q failed: %w", name, call.Err)
	}
	if l := len(call.Body); l != 11 {
		return fmt.Errorf("unexpected arg count %d, want 11", l)
	}

	host, ok := call.Body[5].(string)
	if !ok {
		return fmt.Errorf("wrong type %T for resolved hostname", call.Body[5])
	}
	addrStr, ok := call.Body[7].(string)
	if !ok {
		return fmt.Errorf("wrong type %T for resolved IP", call.Body[7])
	}
	addr := net.ParseIP(addrStr)
	if addr == nil {
		return fmt.Errorf("avahi returned non-IP %q for host %q", addrStr, host)
	}
	port, ok := call.Body[8].(uint16)
	if !ok {
		return fmt.Errorf("wrong type %T for resolved port", call.Body[8])
	}

	ent := dnssd.BrowseEntry{
		IPs:    []net.IP{addr},
		Host:   host,
		Port:   int(port),
		Name:   name,
		Type:   typ,
		Domain: domain,
	}
	s.add(ent)
	return nil
}
