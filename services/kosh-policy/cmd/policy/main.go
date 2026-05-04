package main

import (
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/kosh/policy/internal/server"
	"github.com/kosh/policy/internal/store"
	pb "github.com/kosh/policy/pb"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "50052"
	}
	filePath := os.Getenv("POLICY_FILE")

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("failed to listen on :%s: %v", port, err)
	}

	ps := store.NewPolicyStore(filePath)
	srv := grpc.NewServer()
	pb.RegisterPolicyServiceServer(srv, server.New(ps))
	reflection.Register(srv)

	log.Printf("kosh-policy listening on :%s (file=%q)", port, filePath)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
