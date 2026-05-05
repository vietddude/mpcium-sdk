package protocol

func CloneSessionStart(start *SessionStart) *SessionStart {
	if start == nil {
		return nil
	}
	cloned := *start
	cloned.Participants = CloneParticipants(start.Participants)
	if start.Keygen != nil {
		keygen := *start.Keygen
		cloned.Keygen = &keygen
	}
	if start.Sign != nil {
		sign := *start.Sign
		sign.SigningInput = append([]byte(nil), start.Sign.SigningInput...)
		if start.Sign.Derivation != nil {
			derivation := *start.Sign.Derivation
			derivation.Path = append([]uint32(nil), start.Sign.Derivation.Path...)
			derivation.Delta = append([]byte(nil), start.Sign.Derivation.Delta...)
			sign.Derivation = &derivation
		}
		cloned.Sign = &sign
	}
	if start.Reshare != nil {
		reshare := *start.Reshare
		reshare.NewParticipants = CloneParticipants(start.Reshare.NewParticipants)
		cloned.Reshare = &reshare
	}
	return &cloned
}

func CloneParticipants(participants []*SessionParticipant) []*SessionParticipant {
	out := make([]*SessionParticipant, 0, len(participants))
	for _, participant := range participants {
		if participant == nil {
			continue
		}
		cloned := *participant
		cloned.PartyKey = append([]byte(nil), participant.PartyKey...)
		cloned.IdentityPublicKey = append([]byte(nil), participant.IdentityPublicKey...)
		out = append(out, &cloned)
	}
	return out
}

func CloneProtocolResult(result *Result) *Result {
	if result == nil {
		return nil
	}
	cloned := *result
	if result.KeyShare != nil {
		keyShare := *result.KeyShare
		keyShare.ShareBlob = append([]byte(nil), result.KeyShare.ShareBlob...)
		keyShare.PublicKey = append([]byte(nil), result.KeyShare.PublicKey...)
		cloned.KeyShare = &keyShare
	}
	if result.Signature != nil {
		signature := *result.Signature
		signature.Signature = append([]byte(nil), result.Signature.Signature...)
		signature.SignatureRecovery = append([]byte(nil), result.Signature.SignatureRecovery...)
		signature.R = append([]byte(nil), result.Signature.R...)
		signature.S = append([]byte(nil), result.Signature.S...)
		signature.SignedInput = append([]byte(nil), result.Signature.SignedInput...)
		signature.PublicKey = append([]byte(nil), result.Signature.PublicKey...)
		cloned.Signature = &signature
	}
	return &cloned
}
