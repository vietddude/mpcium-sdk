package participant

import (
	"errors"
	"fmt"

	"github.com/fystack/mpcium-sdk/protocol"
	"github.com/fystack/mpcium-sdk/storage"
)

var ErrPreparamsRotateFailed = errors.New("participant: preparams rotation failed")

// RotatePreparamsSlot promotes nextSlot to active after a decode health-check.
func RotatePreparamsSlot(store storage.PreparamsStore, protocolType protocol.ProtocolType, nextSlot string) error {
	if store == nil {
		return ErrPreparamsRequired
	}
	if nextSlot == "" {
		return fmt.Errorf("%w: missing next slot", ErrPreparamsRotateFailed)
	}

	nextBlob, err := store.LoadPreparamsSlot(protocolType, nextSlot)
	if err != nil {
		return err
	}
	if len(nextBlob) == 0 {
		return fmt.Errorf("%w: empty slot %q", ErrPreparamsRotateFailed, nextSlot)
	}
	if protocolType == protocol.ProtocolTypeECDSA {
		if _, err := decodeECDSAPreparams(nextBlob); err != nil {
			return fmt.Errorf("%w: invalid next preparams: %w", ErrPreparamsRotateFailed, err)
		}
	}

	currentActive, err := store.LoadActivePreparamsSlot(protocolType)
	if err != nil {
		return err
	}
	if currentActive != "" && currentActive != nextSlot {
		prevBlob, err := store.LoadPreparamsSlot(protocolType, currentActive)
		if err != nil {
			return err
		}
		if len(prevBlob) > 0 {
			if err := store.SavePreparamsSlot(protocolType, PreparamsSlotPrev, prevBlob); err != nil {
				return err
			}
		}
	}

	if err := store.SaveActivePreparamsSlot(protocolType, nextSlot); err != nil {
		return err
	}
	confirmedActive, err := store.LoadActivePreparamsSlot(protocolType)
	if err != nil {
		return err
	}
	if confirmedActive != nextSlot {
		return fmt.Errorf("%w: active pointer mismatch %q != %q", ErrPreparamsRotateFailed, confirmedActive, nextSlot)
	}
	return nil
}
