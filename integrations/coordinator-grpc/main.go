package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	coordinatorv1 "github.com/fystack/mpcium-sdk/integrations/coordinator-grpc/proto/coordinator/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	coordinatorAddr = "127.0.0.1:50051"
	signProtocol    = "ECDSA"
	threshold       = uint32(1)
	walletID        = "wallet_grpc_example_3"
	signingInputHex = "6465616462656566" // hex("deadbeef")
	requestTimeout  = 2 * time.Minute
)

var participants = []*coordinatorv1.Participant{
	{
		Id:                   "peer-node-01",
		IdentityPublicKeyHex: "56a47a1103b610d6c85bf23ddb1f78ff6404f7c6f170d46441a268e105873cc4",
	},
	{
		Id:                   "peer-node-02",
		IdentityPublicKeyHex: "d9034dd84e0dd10a57d6a09a8267b217051d5f121ff52fca66c2b485be16ae02",
	},
	// {
	// 	Id:                   "flutter-sample-01",
	// 	IdentityPublicKeyHex: "cad05e95eb9290a4255cf27cf22d269a3b0912e8b4055766e7b0dc5271b18a80",
	// },
}

func main() {
	validateExampleInput()

	conn, err := grpc.NewClient(coordinatorAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("create grpc client: %v", err)
	}
	defer conn.Close()
	client := coordinatorv1.NewCoordinatorOrchestrationClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	keygenResult := runKeygen(ctx, client)
	fmt.Printf("keygen completed: key_id=%s public_key_hex=%s ecdsa_pubkey_hex=%s eddsa_pubkey_hex=%s\n",
		keygenResult.GetKeyId(),
		keygenResult.GetPublicKeyHex(),
		keygenResult.GetEcdsaPubkey(),
		keygenResult.GetEddsaPubkey(),
	)

	signResult := runSign(ctx, client)
	fmt.Printf("sign completed: key_id=%s signature_hex=%s r_hex=%s s_hex=%s\n",
		signResult.GetKeyId(),
		signResult.GetSignatureHex(),
		signResult.GetRHex(),
		signResult.GetSHex(),
	)
}

func runKeygen(ctx context.Context, client coordinatorv1.CoordinatorOrchestrationClient) *coordinatorv1.SessionResult {
	accepted, err := client.Keygen(ctx, &coordinatorv1.KeygenRequest{
		Threshold:    threshold,
		WalletId:     walletID,
		Participants: participants,
	})
	if err != nil {
		log.Fatalf("keygen rpc: %v", err)
	}
	if err := acceptedError("keygen", accepted); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("keygen accepted: session_id=%s expires_at=%s\n", accepted.GetSessionId(), accepted.GetExpiresAt())

	result, err := client.WaitSessionResult(ctx, &coordinatorv1.SessionLookup{SessionId: accepted.GetSessionId()})
	if err != nil {
		log.Fatalf("wait keygen result: %v", err)
	}
	if err := completedError("keygen", result); err != nil {
		log.Fatal(err)
	}
	return result
}

func runSign(ctx context.Context, client coordinatorv1.CoordinatorOrchestrationClient) *coordinatorv1.SessionResult {
	accepted, err := client.Sign(ctx, &coordinatorv1.SignRequest{
		Protocol:        signProtocol,
		Threshold:       threshold,
		WalletId:        walletID,
		SigningInputHex: signingInputHex,
		Participants:    participants,
	})
	if err != nil {
		log.Fatalf("sign rpc: %v", err)
	}
	if err := acceptedError("sign", accepted); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("sign accepted: session_id=%s expires_at=%s\n", accepted.GetSessionId(), accepted.GetExpiresAt())

	result, err := client.WaitSessionResult(ctx, &coordinatorv1.SessionLookup{SessionId: accepted.GetSessionId()})
	if err != nil {
		log.Fatalf("wait sign result: %v", err)
	}
	if err := completedError("sign", result); err != nil {
		log.Fatal(err)
	}
	return result
}

func validateExampleInput() {
	if _, err := hex.DecodeString(signingInputHex); err != nil {
		log.Fatalf("invalid signingInputHex: %v", err)
	}
	for _, participant := range participants {
		if participant.GetId() == "" {
			log.Fatal("participant id is required")
		}
		if _, err := hex.DecodeString(participant.GetIdentityPublicKeyHex()); err != nil {
			log.Fatalf("participant %q invalid identity public key hex: %v", participant.GetId(), err)
		}
	}
}

func acceptedError(op string, accepted *coordinatorv1.RequestAccepted) error {
	if accepted.GetAccepted() {
		return nil
	}
	return fmt.Errorf("%s rejected (%s): %s", op, accepted.GetErrorCode(), accepted.GetErrorMessage())
}

func completedError(op string, result *coordinatorv1.SessionResult) error {
	if result.GetCompleted() {
		return nil
	}
	return fmt.Errorf("%s failed (%s): %s", op, result.GetErrorCode(), result.GetErrorMessage())
}
