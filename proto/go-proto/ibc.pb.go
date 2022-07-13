// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.4
// source: ibc.proto

package go_proto

import (
	types3 "github.com/cosmos/cosmos-sdk/codec/types"
	types2 "github.com/cosmos/ibc-go/v3/modules/core/02-client/types"
	types "github.com/cosmos/ibc-go/v3/modules/core/03-connection/types"
	types1 "github.com/cosmos/ibc-go/v3/modules/core/04-channel/types"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type IBCAction struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Action:
	//	*IBCAction_ConnectionOpenInit
	//	*IBCAction_ConnectionOpenTry
	//	*IBCAction_ConnectionOpenAck
	//	*IBCAction_ConnectionOpenConfirm
	//	*IBCAction_ChannelOpenInit
	//	*IBCAction_ChannelOpenTry
	//	*IBCAction_ChannelOpenAck
	//	*IBCAction_ChannelOpenConfirm
	//	*IBCAction_ChannelCloseInit
	//	*IBCAction_ChannelCloseConfirm
	//	*IBCAction_RecvPacket
	//	*IBCAction_Timeout
	//	*IBCAction_Acknowledgement
	//	*IBCAction_CreateClient
	//	*IBCAction_UpdateClient
	//	*IBCAction_UpgradeClient
	//	*IBCAction_SubmitMisbehaviour
	Action isIBCAction_Action `protobuf_oneof:"action"`
}

func (x *IBCAction) Reset() {
	*x = IBCAction{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ibc_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IBCAction) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IBCAction) ProtoMessage() {}

func (x *IBCAction) ProtoReflect() protoreflect.Message {
	mi := &file_ibc_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IBCAction.ProtoReflect.Descriptor instead.
func (*IBCAction) Descriptor() ([]byte, []int) {
	return file_ibc_proto_rawDescGZIP(), []int{0}
}

func (m *IBCAction) GetAction() isIBCAction_Action {
	if m != nil {
		return m.Action
	}
	return nil
}

func (x *IBCAction) GetConnectionOpenInit() *types.MsgConnectionOpenInit {
	if x, ok := x.GetAction().(*IBCAction_ConnectionOpenInit); ok {
		return x.ConnectionOpenInit
	}
	return nil
}

func (x *IBCAction) GetConnectionOpenTry() *types.MsgConnectionOpenTry {
	if x, ok := x.GetAction().(*IBCAction_ConnectionOpenTry); ok {
		return x.ConnectionOpenTry
	}
	return nil
}

func (x *IBCAction) GetConnectionOpenAck() *types.MsgConnectionOpenAck {
	if x, ok := x.GetAction().(*IBCAction_ConnectionOpenAck); ok {
		return x.ConnectionOpenAck
	}
	return nil
}

func (x *IBCAction) GetConnectionOpenConfirm() *types.MsgConnectionOpenConfirm {
	if x, ok := x.GetAction().(*IBCAction_ConnectionOpenConfirm); ok {
		return x.ConnectionOpenConfirm
	}
	return nil
}

func (x *IBCAction) GetChannelOpenInit() *types1.MsgChannelOpenInit {
	if x, ok := x.GetAction().(*IBCAction_ChannelOpenInit); ok {
		return x.ChannelOpenInit
	}
	return nil
}

func (x *IBCAction) GetChannelOpenTry() *types1.MsgChannelOpenTry {
	if x, ok := x.GetAction().(*IBCAction_ChannelOpenTry); ok {
		return x.ChannelOpenTry
	}
	return nil
}

func (x *IBCAction) GetChannelOpenAck() *types1.MsgChannelOpenAck {
	if x, ok := x.GetAction().(*IBCAction_ChannelOpenAck); ok {
		return x.ChannelOpenAck
	}
	return nil
}

func (x *IBCAction) GetChannelOpenConfirm() *types1.MsgChannelOpenConfirm {
	if x, ok := x.GetAction().(*IBCAction_ChannelOpenConfirm); ok {
		return x.ChannelOpenConfirm
	}
	return nil
}

func (x *IBCAction) GetChannelCloseInit() *types1.MsgChannelCloseInit {
	if x, ok := x.GetAction().(*IBCAction_ChannelCloseInit); ok {
		return x.ChannelCloseInit
	}
	return nil
}

func (x *IBCAction) GetChannelCloseConfirm() *types1.MsgChannelCloseConfirm {
	if x, ok := x.GetAction().(*IBCAction_ChannelCloseConfirm); ok {
		return x.ChannelCloseConfirm
	}
	return nil
}

func (x *IBCAction) GetRecvPacket() *types1.MsgRecvPacket {
	if x, ok := x.GetAction().(*IBCAction_RecvPacket); ok {
		return x.RecvPacket
	}
	return nil
}

func (x *IBCAction) GetTimeout() *types1.MsgTimeout {
	if x, ok := x.GetAction().(*IBCAction_Timeout); ok {
		return x.Timeout
	}
	return nil
}

func (x *IBCAction) GetAcknowledgement() *types1.MsgAcknowledgement {
	if x, ok := x.GetAction().(*IBCAction_Acknowledgement); ok {
		return x.Acknowledgement
	}
	return nil
}

func (x *IBCAction) GetCreateClient() *types2.MsgCreateClient {
	if x, ok := x.GetAction().(*IBCAction_CreateClient); ok {
		return x.CreateClient
	}
	return nil
}

func (x *IBCAction) GetUpdateClient() *types2.MsgUpdateClient {
	if x, ok := x.GetAction().(*IBCAction_UpdateClient); ok {
		return x.UpdateClient
	}
	return nil
}

func (x *IBCAction) GetUpgradeClient() *types2.MsgUpgradeClient {
	if x, ok := x.GetAction().(*IBCAction_UpgradeClient); ok {
		return x.UpgradeClient
	}
	return nil
}

func (x *IBCAction) GetSubmitMisbehaviour() *types2.MsgSubmitMisbehaviour {
	if x, ok := x.GetAction().(*IBCAction_SubmitMisbehaviour); ok {
		return x.SubmitMisbehaviour
	}
	return nil
}

type isIBCAction_Action interface {
	isIBCAction_Action()
}

type IBCAction_ConnectionOpenInit struct {
	ConnectionOpenInit *types.MsgConnectionOpenInit `protobuf:"bytes,1,opt,name=connectionOpenInit,proto3,oneof"`
}

type IBCAction_ConnectionOpenTry struct {
	ConnectionOpenTry *types.MsgConnectionOpenTry `protobuf:"bytes,2,opt,name=connectionOpenTry,proto3,oneof"`
}

type IBCAction_ConnectionOpenAck struct {
	ConnectionOpenAck *types.MsgConnectionOpenAck `protobuf:"bytes,3,opt,name=connectionOpenAck,proto3,oneof"`
}

type IBCAction_ConnectionOpenConfirm struct {
	ConnectionOpenConfirm *types.MsgConnectionOpenConfirm `protobuf:"bytes,4,opt,name=connectionOpenConfirm,proto3,oneof"`
}

type IBCAction_ChannelOpenInit struct {
	ChannelOpenInit *types1.MsgChannelOpenInit `protobuf:"bytes,5,opt,name=channelOpenInit,proto3,oneof"`
}

type IBCAction_ChannelOpenTry struct {
	ChannelOpenTry *types1.MsgChannelOpenTry `protobuf:"bytes,6,opt,name=channelOpenTry,proto3,oneof"`
}

type IBCAction_ChannelOpenAck struct {
	ChannelOpenAck *types1.MsgChannelOpenAck `protobuf:"bytes,7,opt,name=channelOpenAck,proto3,oneof"`
}

type IBCAction_ChannelOpenConfirm struct {
	ChannelOpenConfirm *types1.MsgChannelOpenConfirm `protobuf:"bytes,8,opt,name=channelOpenConfirm,proto3,oneof"`
}

type IBCAction_ChannelCloseInit struct {
	ChannelCloseInit *types1.MsgChannelCloseInit `protobuf:"bytes,9,opt,name=channelCloseInit,proto3,oneof"`
}

type IBCAction_ChannelCloseConfirm struct {
	ChannelCloseConfirm *types1.MsgChannelCloseConfirm `protobuf:"bytes,10,opt,name=channelCloseConfirm,proto3,oneof"`
}

type IBCAction_RecvPacket struct {
	RecvPacket *types1.MsgRecvPacket `protobuf:"bytes,11,opt,name=recvPacket,proto3,oneof"`
}

type IBCAction_Timeout struct {
	Timeout *types1.MsgTimeout `protobuf:"bytes,12,opt,name=timeout,proto3,oneof"`
}

type IBCAction_Acknowledgement struct {
	Acknowledgement *types1.MsgAcknowledgement `protobuf:"bytes,13,opt,name=acknowledgement,proto3,oneof"`
}

type IBCAction_CreateClient struct {
	CreateClient *types2.MsgCreateClient `protobuf:"bytes,14,opt,name=createClient,proto3,oneof"`
}

type IBCAction_UpdateClient struct {
	UpdateClient *types2.MsgUpdateClient `protobuf:"bytes,15,opt,name=updateClient,proto3,oneof"`
}

type IBCAction_UpgradeClient struct {
	UpgradeClient *types2.MsgUpgradeClient `protobuf:"bytes,16,opt,name=upgradeClient,proto3,oneof"`
}

type IBCAction_SubmitMisbehaviour struct {
	SubmitMisbehaviour *types2.MsgSubmitMisbehaviour `protobuf:"bytes,17,opt,name=submitMisbehaviour,proto3,oneof"`
}

func (*IBCAction_ConnectionOpenInit) isIBCAction_Action() {}

func (*IBCAction_ConnectionOpenTry) isIBCAction_Action() {}

func (*IBCAction_ConnectionOpenAck) isIBCAction_Action() {}

func (*IBCAction_ConnectionOpenConfirm) isIBCAction_Action() {}

func (*IBCAction_ChannelOpenInit) isIBCAction_Action() {}

func (*IBCAction_ChannelOpenTry) isIBCAction_Action() {}

func (*IBCAction_ChannelOpenAck) isIBCAction_Action() {}

func (*IBCAction_ChannelOpenConfirm) isIBCAction_Action() {}

func (*IBCAction_ChannelCloseInit) isIBCAction_Action() {}

func (*IBCAction_ChannelCloseConfirm) isIBCAction_Action() {}

func (*IBCAction_RecvPacket) isIBCAction_Action() {}

func (*IBCAction_Timeout) isIBCAction_Action() {}

func (*IBCAction_Acknowledgement) isIBCAction_Action() {}

func (*IBCAction_CreateClient) isIBCAction_Action() {}

func (*IBCAction_UpdateClient) isIBCAction_Action() {}

func (*IBCAction_UpgradeClient) isIBCAction_Action() {}

func (*IBCAction_SubmitMisbehaviour) isIBCAction_Action() {}

type ClientData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ClientID        string      `protobuf:"bytes,1,opt,name=clientID,proto3" json:"clientID,omitempty"`
	ClientState     *types3.Any `protobuf:"bytes,2,opt,name=clientState,proto3" json:"clientState,omitempty"` // NOTE: left as Any to allow us to add more client types later
	ProcessedTime   string      `protobuf:"bytes,3,opt,name=processedTime,proto3" json:"processedTime,omitempty"`
	ProcessedHeight uint64      `protobuf:"varint,4,opt,name=processedHeight,proto3" json:"processedHeight,omitempty"`
}

func (x *ClientData) Reset() {
	*x = ClientData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ibc_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientData) ProtoMessage() {}

func (x *ClientData) ProtoReflect() protoreflect.Message {
	mi := &file_ibc_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientData.ProtoReflect.Descriptor instead.
func (*ClientData) Descriptor() ([]byte, []int) {
	return file_ibc_proto_rawDescGZIP(), []int{1}
}

func (x *ClientData) GetClientID() string {
	if x != nil {
		return x.ClientID
	}
	return ""
}

func (x *ClientData) GetClientState() *types3.Any {
	if x != nil {
		return x.ClientState
	}
	return nil
}

func (x *ClientData) GetProcessedTime() string {
	if x != nil {
		return x.ProcessedTime
	}
	return ""
}

func (x *ClientData) GetProcessedHeight() uint64 {
	if x != nil {
		return x.ProcessedHeight
	}
	return 0
}

type ClientCounter struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Counter uint64 `protobuf:"varint,1,opt,name=counter,proto3" json:"counter,omitempty"`
}

func (x *ClientCounter) Reset() {
	*x = ClientCounter{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ibc_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientCounter) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientCounter) ProtoMessage() {}

func (x *ClientCounter) ProtoReflect() protoreflect.Message {
	mi := &file_ibc_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientCounter.ProtoReflect.Descriptor instead.
func (*ClientCounter) Descriptor() ([]byte, []int) {
	return file_ibc_proto_rawDescGZIP(), []int{2}
}

func (x *ClientCounter) GetCounter() uint64 {
	if x != nil {
		return x.Counter
	}
	return 0
}

type ConsensusState struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ConsensusState *types3.Any `protobuf:"bytes,1,opt,name=consensusState,proto3" json:"consensusState,omitempty"`
}

func (x *ConsensusState) Reset() {
	*x = ConsensusState{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ibc_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConsensusState) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConsensusState) ProtoMessage() {}

func (x *ConsensusState) ProtoReflect() protoreflect.Message {
	mi := &file_ibc_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConsensusState.ProtoReflect.Descriptor instead.
func (*ConsensusState) Descriptor() ([]byte, []int) {
	return file_ibc_proto_rawDescGZIP(), []int{3}
}

func (x *ConsensusState) GetConsensusState() *types3.Any {
	if x != nil {
		return x.ConsensusState
	}
	return nil
}

type VerifiedHeights struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Heights []*types2.Height `protobuf:"bytes,1,rep,name=heights,proto3" json:"heights,omitempty"`
}

func (x *VerifiedHeights) Reset() {
	*x = VerifiedHeights{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ibc_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VerifiedHeights) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerifiedHeights) ProtoMessage() {}

func (x *VerifiedHeights) ProtoReflect() protoreflect.Message {
	mi := &file_ibc_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VerifiedHeights.ProtoReflect.Descriptor instead.
func (*VerifiedHeights) Descriptor() ([]byte, []int) {
	return file_ibc_proto_rawDescGZIP(), []int{4}
}

func (x *VerifiedHeights) GetHeights() []*types2.Height {
	if x != nil {
		return x.Heights
	}
	return nil
}

type ConnectionCounter struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Counter uint64 `protobuf:"varint,1,opt,name=counter,proto3" json:"counter,omitempty"`
}

func (x *ConnectionCounter) Reset() {
	*x = ConnectionCounter{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ibc_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConnectionCounter) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConnectionCounter) ProtoMessage() {}

func (x *ConnectionCounter) ProtoReflect() protoreflect.Message {
	mi := &file_ibc_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConnectionCounter.ProtoReflect.Descriptor instead.
func (*ConnectionCounter) Descriptor() ([]byte, []int) {
	return file_ibc_proto_rawDescGZIP(), []int{5}
}

func (x *ConnectionCounter) GetCounter() uint64 {
	if x != nil {
		return x.Counter
	}
	return 0
}

type ClientConnections struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Connections []string `protobuf:"bytes,1,rep,name=connections,proto3" json:"connections,omitempty"`
}

func (x *ClientConnections) Reset() {
	*x = ClientConnections{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ibc_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientConnections) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientConnections) ProtoMessage() {}

func (x *ClientConnections) ProtoReflect() protoreflect.Message {
	mi := &file_ibc_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientConnections.ProtoReflect.Descriptor instead.
func (*ClientConnections) Descriptor() ([]byte, []int) {
	return file_ibc_proto_rawDescGZIP(), []int{6}
}

func (x *ClientConnections) GetConnections() []string {
	if x != nil {
		return x.Connections
	}
	return nil
}

var File_ibc_proto protoreflect.FileDescriptor

var file_ibc_proto_rawDesc = []byte{
	0x0a, 0x09, 0x69, 0x62, 0x63, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x70, 0x65, 0x6e,
	0x75, 0x6d, 0x62, 0x72, 0x61, 0x2e, 0x69, 0x62, 0x63, 0x1a, 0x1f, 0x69, 0x62, 0x63, 0x2f, 0x63,
	0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76,
	0x31, 0x2f, 0x74, 0x78, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x27, 0x69, 0x62, 0x63, 0x2f,
	0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2f,
	0x76, 0x31, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x69, 0x62, 0x63, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x68,
	0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x78, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1b, 0x69, 0x62, 0x63, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x78, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f,
	0x69, 0x62, 0x63, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2f,
	0x76, 0x31, 0x2f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc5, 0x0b, 0x0a, 0x09, 0x49,
	0x42, 0x43, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x5f, 0x0a, 0x12, 0x63, 0x6f, 0x6e, 0x6e,
	0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4f, 0x70, 0x65, 0x6e, 0x49, 0x6e, 0x69, 0x74, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x69, 0x62, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e,
	0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x73,
	0x67, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4f, 0x70, 0x65, 0x6e, 0x49,
	0x6e, 0x69, 0x74, 0x48, 0x00, 0x52, 0x12, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x4f, 0x70, 0x65, 0x6e, 0x49, 0x6e, 0x69, 0x74, 0x12, 0x5c, 0x0a, 0x11, 0x63, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x72, 0x79, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x2c, 0x2e, 0x69, 0x62, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e,
	0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x73,
	0x67, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4f, 0x70, 0x65, 0x6e, 0x54,
	0x72, 0x79, 0x48, 0x00, 0x52, 0x11, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x4f, 0x70, 0x65, 0x6e, 0x54, 0x72, 0x79, 0x12, 0x5c, 0x0a, 0x11, 0x63, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4f, 0x70, 0x65, 0x6e, 0x41, 0x63, 0x6b, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x2c, 0x2e, 0x69, 0x62, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f,
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x73, 0x67, 0x43,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4f, 0x70, 0x65, 0x6e, 0x41, 0x63, 0x6b,
	0x48, 0x00, 0x52, 0x11, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4f, 0x70,
	0x65, 0x6e, 0x41, 0x63, 0x6b, 0x12, 0x68, 0x0a, 0x15, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x4f, 0x70, 0x65, 0x6e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x30, 0x2e, 0x69, 0x62, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e,
	0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x73,
	0x67, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4f, 0x70, 0x65, 0x6e, 0x43,
	0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x48, 0x00, 0x52, 0x15, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x4f, 0x70, 0x65, 0x6e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x12,
	0x53, 0x0a, 0x0f, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x4f, 0x70, 0x65, 0x6e, 0x49, 0x6e,
	0x69, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x69, 0x62, 0x63, 0x2e, 0x63,
	0x6f, 0x72, 0x65, 0x2e, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x4d,
	0x73, 0x67, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x4f, 0x70, 0x65, 0x6e, 0x49, 0x6e, 0x69,
	0x74, 0x48, 0x00, 0x52, 0x0f, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x4f, 0x70, 0x65, 0x6e,
	0x49, 0x6e, 0x69, 0x74, 0x12, 0x50, 0x0a, 0x0e, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x4f,
	0x70, 0x65, 0x6e, 0x54, 0x72, 0x79, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x26, 0x2e, 0x69,
	0x62, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x2e,
	0x76, 0x31, 0x2e, 0x4d, 0x73, 0x67, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x4f, 0x70, 0x65,
	0x6e, 0x54, 0x72, 0x79, 0x48, 0x00, 0x52, 0x0e, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x4f,
	0x70, 0x65, 0x6e, 0x54, 0x72, 0x79, 0x12, 0x50, 0x0a, 0x0e, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65,
	0x6c, 0x4f, 0x70, 0x65, 0x6e, 0x41, 0x63, 0x6b, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x26,
	0x2e, 0x69, 0x62, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65,
	0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x73, 0x67, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x4f,
	0x70, 0x65, 0x6e, 0x41, 0x63, 0x6b, 0x48, 0x00, 0x52, 0x0e, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65,
	0x6c, 0x4f, 0x70, 0x65, 0x6e, 0x41, 0x63, 0x6b, 0x12, 0x5c, 0x0a, 0x12, 0x63, 0x68, 0x61, 0x6e,
	0x6e, 0x65, 0x6c, 0x4f, 0x70, 0x65, 0x6e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x69, 0x62, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e,
	0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x73, 0x67, 0x43, 0x68,
	0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x4f, 0x70, 0x65, 0x6e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d,
	0x48, 0x00, 0x52, 0x12, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x4f, 0x70, 0x65, 0x6e, 0x43,
	0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x12, 0x56, 0x0a, 0x10, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65,
	0x6c, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x49, 0x6e, 0x69, 0x74, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x28, 0x2e, 0x69, 0x62, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x68, 0x61, 0x6e,
	0x6e, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x73, 0x67, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65,
	0x6c, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x49, 0x6e, 0x69, 0x74, 0x48, 0x00, 0x52, 0x10, 0x63, 0x68,
	0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x49, 0x6e, 0x69, 0x74, 0x12, 0x5f,
	0x0a, 0x13, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x72, 0x6d, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2b, 0x2e, 0x69, 0x62,
	0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x2e, 0x76,
	0x31, 0x2e, 0x4d, 0x73, 0x67, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x43, 0x6c, 0x6f, 0x73,
	0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x48, 0x00, 0x52, 0x13, 0x63, 0x68, 0x61, 0x6e,
	0x6e, 0x65, 0x6c, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x12,
	0x44, 0x0a, 0x0a, 0x72, 0x65, 0x63, 0x76, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x18, 0x0b, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x69, 0x62, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63,
	0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x73, 0x67, 0x52, 0x65, 0x63,
	0x76, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x48, 0x00, 0x52, 0x0a, 0x72, 0x65, 0x63, 0x76, 0x50,
	0x61, 0x63, 0x6b, 0x65, 0x74, 0x12, 0x3b, 0x0a, 0x07, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74,
	0x18, 0x0c, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x69, 0x62, 0x63, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x2e, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x73, 0x67,
	0x54, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x48, 0x00, 0x52, 0x07, 0x74, 0x69, 0x6d, 0x65, 0x6f,
	0x75, 0x74, 0x12, 0x53, 0x0a, 0x0f, 0x61, 0x63, 0x6b, 0x6e, 0x6f, 0x77, 0x6c, 0x65, 0x64, 0x67,
	0x65, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x69, 0x62,
	0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x2e, 0x76,
	0x31, 0x2e, 0x4d, 0x73, 0x67, 0x41, 0x63, 0x6b, 0x6e, 0x6f, 0x77, 0x6c, 0x65, 0x64, 0x67, 0x65,
	0x6d, 0x65, 0x6e, 0x74, 0x48, 0x00, 0x52, 0x0f, 0x61, 0x63, 0x6b, 0x6e, 0x6f, 0x77, 0x6c, 0x65,
	0x64, 0x67, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x49, 0x0a, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e,
	0x69, 0x62, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e,
	0x76, 0x31, 0x2e, 0x4d, 0x73, 0x67, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x43, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x48, 0x00, 0x52, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x43, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x12, 0x49, 0x0a, 0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x43, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x69, 0x62, 0x63, 0x2e, 0x63,
	0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x73,
	0x67, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x48, 0x00, 0x52,
	0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x12, 0x4c, 0x0a,
	0x0d, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x18, 0x10,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x69, 0x62, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e,
	0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x73, 0x67, 0x55, 0x70, 0x67,
	0x72, 0x61, 0x64, 0x65, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x48, 0x00, 0x52, 0x0d, 0x75, 0x70,
	0x67, 0x72, 0x61, 0x64, 0x65, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x12, 0x5b, 0x0a, 0x12, 0x73,
	0x75, 0x62, 0x6d, 0x69, 0x74, 0x4d, 0x69, 0x73, 0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x75,
	0x72, 0x18, 0x11, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x69, 0x62, 0x63, 0x2e, 0x63, 0x6f,
	0x72, 0x65, 0x2e, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x73, 0x67,
	0x53, 0x75, 0x62, 0x6d, 0x69, 0x74, 0x4d, 0x69, 0x73, 0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6f,
	0x75, 0x72, 0x48, 0x00, 0x52, 0x12, 0x73, 0x75, 0x62, 0x6d, 0x69, 0x74, 0x4d, 0x69, 0x73, 0x62,
	0x65, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x75, 0x72, 0x42, 0x08, 0x0a, 0x06, 0x61, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x22, 0xb0, 0x01, 0x0a, 0x0a, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x44, 0x61, 0x74,
	0x61, 0x12, 0x1a, 0x0a, 0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x44, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x44, 0x12, 0x36, 0x0a,
	0x0b, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x53, 0x74, 0x61, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52, 0x0b, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x24, 0x0a, 0x0d, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73,
	0x65, 0x64, 0x54, 0x69, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x70, 0x72,
	0x6f, 0x63, 0x65, 0x73, 0x73, 0x65, 0x64, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x28, 0x0a, 0x0f, 0x70,
	0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x65, 0x64, 0x48, 0x65, 0x69, 0x67, 0x68, 0x74, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x0f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x65, 0x64, 0x48,
	0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x29, 0x0a, 0x0d, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x43,
	0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65,
	0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72,
	0x22, 0x4e, 0x0a, 0x0e, 0x43, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x53, 0x74, 0x61,
	0x74, 0x65, 0x12, 0x3c, 0x0a, 0x0e, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x53,
	0x74, 0x61, 0x74, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79,
	0x52, 0x0e, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x53, 0x74, 0x61, 0x74, 0x65,
	0x22, 0x47, 0x0a, 0x0f, 0x56, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x64, 0x48, 0x65, 0x69, 0x67,
	0x68, 0x74, 0x73, 0x12, 0x34, 0x0a, 0x07, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x73, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x69, 0x62, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e,
	0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x65, 0x69, 0x67, 0x68, 0x74,
	0x52, 0x07, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x73, 0x22, 0x2d, 0x0a, 0x11, 0x43, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x12, 0x18,
	0x0a, 0x07, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x07, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x22, 0x35, 0x0a, 0x11, 0x43, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x20, 0x0a,
	0x0b, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x09, 0x52, 0x0b, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x42,
	0x32, 0x5a, 0x30, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x65,
	0x6e, 0x75, 0x6d, 0x62, 0x72, 0x61, 0x2d, 0x7a, 0x6f, 0x6e, 0x65, 0x2f, 0x70, 0x65, 0x6e, 0x75,
	0x6d, 0x62, 0x72, 0x61, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2d, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ibc_proto_rawDescOnce sync.Once
	file_ibc_proto_rawDescData = file_ibc_proto_rawDesc
)

func file_ibc_proto_rawDescGZIP() []byte {
	file_ibc_proto_rawDescOnce.Do(func() {
		file_ibc_proto_rawDescData = protoimpl.X.CompressGZIP(file_ibc_proto_rawDescData)
	})
	return file_ibc_proto_rawDescData
}

var file_ibc_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_ibc_proto_goTypes = []interface{}{
	(*IBCAction)(nil),                      // 0: penumbra.ibc.IBCAction
	(*ClientData)(nil),                     // 1: penumbra.ibc.ClientData
	(*ClientCounter)(nil),                  // 2: penumbra.ibc.ClientCounter
	(*ConsensusState)(nil),                 // 3: penumbra.ibc.ConsensusState
	(*VerifiedHeights)(nil),                // 4: penumbra.ibc.VerifiedHeights
	(*ConnectionCounter)(nil),              // 5: penumbra.ibc.ConnectionCounter
	(*ClientConnections)(nil),              // 6: penumbra.ibc.ClientConnections
	(*types.MsgConnectionOpenInit)(nil),    // 7: ibc.core.connection.v1.MsgConnectionOpenInit
	(*types.MsgConnectionOpenTry)(nil),     // 8: ibc.core.connection.v1.MsgConnectionOpenTry
	(*types.MsgConnectionOpenAck)(nil),     // 9: ibc.core.connection.v1.MsgConnectionOpenAck
	(*types.MsgConnectionOpenConfirm)(nil), // 10: ibc.core.connection.v1.MsgConnectionOpenConfirm
	(*types1.MsgChannelOpenInit)(nil),      // 11: ibc.core.channel.v1.MsgChannelOpenInit
	(*types1.MsgChannelOpenTry)(nil),       // 12: ibc.core.channel.v1.MsgChannelOpenTry
	(*types1.MsgChannelOpenAck)(nil),       // 13: ibc.core.channel.v1.MsgChannelOpenAck
	(*types1.MsgChannelOpenConfirm)(nil),   // 14: ibc.core.channel.v1.MsgChannelOpenConfirm
	(*types1.MsgChannelCloseInit)(nil),     // 15: ibc.core.channel.v1.MsgChannelCloseInit
	(*types1.MsgChannelCloseConfirm)(nil),  // 16: ibc.core.channel.v1.MsgChannelCloseConfirm
	(*types1.MsgRecvPacket)(nil),           // 17: ibc.core.channel.v1.MsgRecvPacket
	(*types1.MsgTimeout)(nil),              // 18: ibc.core.channel.v1.MsgTimeout
	(*types1.MsgAcknowledgement)(nil),      // 19: ibc.core.channel.v1.MsgAcknowledgement
	(*types2.MsgCreateClient)(nil),         // 20: ibc.core.client.v1.MsgCreateClient
	(*types2.MsgUpdateClient)(nil),         // 21: ibc.core.client.v1.MsgUpdateClient
	(*types2.MsgUpgradeClient)(nil),        // 22: ibc.core.client.v1.MsgUpgradeClient
	(*types2.MsgSubmitMisbehaviour)(nil),   // 23: ibc.core.client.v1.MsgSubmitMisbehaviour
	(*types3.Any)(nil),                     // 24: google.protobuf.Any
	(*types2.Height)(nil),                  // 25: ibc.core.client.v1.Height
}
var file_ibc_proto_depIdxs = []int32{
	7,  // 0: penumbra.ibc.IBCAction.connectionOpenInit:type_name -> ibc.core.connection.v1.MsgConnectionOpenInit
	8,  // 1: penumbra.ibc.IBCAction.connectionOpenTry:type_name -> ibc.core.connection.v1.MsgConnectionOpenTry
	9,  // 2: penumbra.ibc.IBCAction.connectionOpenAck:type_name -> ibc.core.connection.v1.MsgConnectionOpenAck
	10, // 3: penumbra.ibc.IBCAction.connectionOpenConfirm:type_name -> ibc.core.connection.v1.MsgConnectionOpenConfirm
	11, // 4: penumbra.ibc.IBCAction.channelOpenInit:type_name -> ibc.core.channel.v1.MsgChannelOpenInit
	12, // 5: penumbra.ibc.IBCAction.channelOpenTry:type_name -> ibc.core.channel.v1.MsgChannelOpenTry
	13, // 6: penumbra.ibc.IBCAction.channelOpenAck:type_name -> ibc.core.channel.v1.MsgChannelOpenAck
	14, // 7: penumbra.ibc.IBCAction.channelOpenConfirm:type_name -> ibc.core.channel.v1.MsgChannelOpenConfirm
	15, // 8: penumbra.ibc.IBCAction.channelCloseInit:type_name -> ibc.core.channel.v1.MsgChannelCloseInit
	16, // 9: penumbra.ibc.IBCAction.channelCloseConfirm:type_name -> ibc.core.channel.v1.MsgChannelCloseConfirm
	17, // 10: penumbra.ibc.IBCAction.recvPacket:type_name -> ibc.core.channel.v1.MsgRecvPacket
	18, // 11: penumbra.ibc.IBCAction.timeout:type_name -> ibc.core.channel.v1.MsgTimeout
	19, // 12: penumbra.ibc.IBCAction.acknowledgement:type_name -> ibc.core.channel.v1.MsgAcknowledgement
	20, // 13: penumbra.ibc.IBCAction.createClient:type_name -> ibc.core.client.v1.MsgCreateClient
	21, // 14: penumbra.ibc.IBCAction.updateClient:type_name -> ibc.core.client.v1.MsgUpdateClient
	22, // 15: penumbra.ibc.IBCAction.upgradeClient:type_name -> ibc.core.client.v1.MsgUpgradeClient
	23, // 16: penumbra.ibc.IBCAction.submitMisbehaviour:type_name -> ibc.core.client.v1.MsgSubmitMisbehaviour
	24, // 17: penumbra.ibc.ClientData.clientState:type_name -> google.protobuf.Any
	24, // 18: penumbra.ibc.ConsensusState.consensusState:type_name -> google.protobuf.Any
	25, // 19: penumbra.ibc.VerifiedHeights.heights:type_name -> ibc.core.client.v1.Height
	20, // [20:20] is the sub-list for method output_type
	20, // [20:20] is the sub-list for method input_type
	20, // [20:20] is the sub-list for extension type_name
	20, // [20:20] is the sub-list for extension extendee
	0,  // [0:20] is the sub-list for field type_name
}

func init() { file_ibc_proto_init() }
func file_ibc_proto_init() {
	if File_ibc_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ibc_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IBCAction); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ibc_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClientData); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ibc_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClientCounter); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ibc_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConsensusState); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ibc_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VerifiedHeights); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ibc_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConnectionCounter); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ibc_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClientConnections); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_ibc_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*IBCAction_ConnectionOpenInit)(nil),
		(*IBCAction_ConnectionOpenTry)(nil),
		(*IBCAction_ConnectionOpenAck)(nil),
		(*IBCAction_ConnectionOpenConfirm)(nil),
		(*IBCAction_ChannelOpenInit)(nil),
		(*IBCAction_ChannelOpenTry)(nil),
		(*IBCAction_ChannelOpenAck)(nil),
		(*IBCAction_ChannelOpenConfirm)(nil),
		(*IBCAction_ChannelCloseInit)(nil),
		(*IBCAction_ChannelCloseConfirm)(nil),
		(*IBCAction_RecvPacket)(nil),
		(*IBCAction_Timeout)(nil),
		(*IBCAction_Acknowledgement)(nil),
		(*IBCAction_CreateClient)(nil),
		(*IBCAction_UpdateClient)(nil),
		(*IBCAction_UpgradeClient)(nil),
		(*IBCAction_SubmitMisbehaviour)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_ibc_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ibc_proto_goTypes,
		DependencyIndexes: file_ibc_proto_depIdxs,
		MessageInfos:      file_ibc_proto_msgTypes,
	}.Build()
	File_ibc_proto = out.File
	file_ibc_proto_rawDesc = nil
	file_ibc_proto_goTypes = nil
	file_ibc_proto_depIdxs = nil
}
