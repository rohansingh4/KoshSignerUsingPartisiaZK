package main

import (
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/kosh/coordinator/internal/bb"
	pb "github.com/kosh/coordinator/pb"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "50051"
	}

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("failed to listen on :%s: %v", port, err)
	}

	srv := grpc.NewServer()
	pb.RegisterBulletinBoardServer(srv, bb.NewServer())

	// Reflection lets grpcurl introspect the service without a proto file.
	reflection.Register(srv)

	log.Printf("kosh-coordinator listening on :%s", port)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
