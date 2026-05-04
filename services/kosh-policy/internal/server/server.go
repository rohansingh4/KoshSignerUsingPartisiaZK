package server

import (
	"context"

	pb "github.com/kosh/policy/pb"
	"github.com/kosh/policy/internal/store"
)

type Server struct {
	pb.UnimplementedPolicyServiceServer
	store *store.PolicyStore
}

func New(ps *store.PolicyStore) *Server {
	return &Server{store: ps}
}

func (s *Server) AddPolicy(_ context.Context, req *pb.AddPolicyRequest) (*pb.AddPolicyResponse, error) {
	p := req.Policy
	id := s.store.Add(store.Policy{
		Name:             p.Name,
		TxTag:            p.TxTag,
		MandatoryParties: p.MandatoryParties,
		MinThreshold:     p.MinThreshold,
	})
	return &pb.AddPolicyResponse{Id: id}, nil
}

func (s *Server) RemovePolicy(_ context.Context, req *pb.RemovePolicyRequest) (*pb.RemovePolicyResponse, error) {
	ok := s.store.Remove(req.Id)
	return &pb.RemovePolicyResponse{Ok: ok}, nil
}

func (s *Server) ListPolicies(_ context.Context, _ *pb.ListPoliciesRequest) (*pb.ListPoliciesResponse, error) {
	list := s.store.List()
	out := make([]*pb.Policy, len(list))
	for i, p := range list {
		out[i] = &pb.Policy{
			Id:               p.ID,
			Name:             p.Name,
			TxTag:            p.TxTag,
			MandatoryParties: p.MandatoryParties,
			MinThreshold:     p.MinThreshold,
			CreatedAt:        p.CreatedAt,
		}
	}
	return &pb.ListPoliciesResponse{Policies: out}, nil
}

func (s *Server) Validate(_ context.Context, req *pb.ValidateRequest) (*pb.ValidateResponse, error) {
	violation := s.store.Validate(req.TxTag, req.SigningParties)
	if violation == nil {
		return &pb.ValidateResponse{Ok: true}, nil
	}
	return &pb.ValidateResponse{
		Ok:               false,
		ViolationMessage: violation.Message,
		MissingParties:   violation.MissingParties,
	}, nil
}
