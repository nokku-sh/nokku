// Package auth wires kagi (the shared authentication engine) into nokku's
// database and request model. It implements kagi.Store and kagi.APIKeyStore
// against sqlc, and defines the principal kinds nokku recognizes.
package auth

import "github.com/mizuchilabs/kagi"

// Principal kinds nokku recognizes, mapped onto kagi.Kind. They mirror
// meta.ActorType so a kagi.Principal converts to an actor 1:1.
const (
	KindUser           kagi.Kind = "user"
	KindServiceAccount kagi.Kind = "service_account"
	KindDaemon         kagi.Kind = "daemon"
	KindDevice         kagi.Kind = "device"
)
