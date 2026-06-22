package controlv1

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
)

const (
	ControlServiceName = "aegis.control.v1.ControlService"
	CodecName          = "json"
)

func init() {
	encoding.RegisterCodec(jsonCodec{})
}

type HealthRequest struct{}

type HealthResponse struct {
	Status  string `json:"status,omitempty"`
	Version string `json:"version,omitempty"`
}

func (x *HealthResponse) GetStatus() string {
	if x != nil {
		return x.Status
	}
	return ""
}

func (x *HealthResponse) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

type ControlServiceClient interface {
	Health(ctx context.Context, in *HealthRequest, opts ...grpc.CallOption) (*HealthResponse, error)
}

type controlServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewControlServiceClient(cc grpc.ClientConnInterface) ControlServiceClient {
	return &controlServiceClient{cc: cc}
}

func (c *controlServiceClient) Health(ctx context.Context, in *HealthRequest, opts ...grpc.CallOption) (*HealthResponse, error) {
	out := new(HealthResponse)
	opts = append([]grpc.CallOption{grpc.ForceCodec(jsonCodec{})}, opts...)
	if err := c.cc.Invoke(ctx, "/aegis.control.v1.ControlService/Health", in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

type ControlServiceServer interface {
	Health(context.Context, *HealthRequest) (*HealthResponse, error)
}

func RegisterControlServiceServer(s grpc.ServiceRegistrar, srv ControlServiceServer) {
	s.RegisterService(&ControlService_ServiceDesc, srv)
}

func _ControlService_Health_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(HealthRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ControlServiceServer).Health(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/aegis.control.v1.ControlService/Health",
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(ControlServiceServer).Health(ctx, req.(*HealthRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var ControlService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: ControlServiceName,
	HandlerType: (*ControlServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Health",
			Handler:    _ControlService_Health_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/control/v1/control.proto",
}

type jsonCodec struct{}

func (jsonCodec) Name() string {
	return CodecName
}

func (jsonCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
