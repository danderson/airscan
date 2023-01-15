package main

import (
	"context"
	"errors"
	"log"

	"github.com/brutella/dnssd"
	"github.com/davecgh/go-spew/spew"
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
	return discover(ctx, add, rm)
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
