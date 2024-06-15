package wallet

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"

	"github.com/xssnick/tonutils-go/tvm/cell"
)

// non verified contract do not use yet
// use official from here once ready (base64 decode): https://github.com/tonkeeper/tonkeeper-ton/blob/master/src/wallets/WalletContractV5.ts#L81
const _V5R1CodeHex = "b5ee9c7241021301000226000114ff00f4a413f4bcf2c80b0102012004020102f203011420d728239b4b3b74307f0f0201480e050201200706001bbe5f0f6a2684080b8eb90fa021840201200b080201200a090019b45d1da89a10043ae43ae169f00017b592fda89a0e3ae43ae163f00202760d0c0012a880ed44d0d70a00b30018ab9ced44d08071d721d70bff028ed020c702dc01d0d60301c713dc01d72c232bc3a3748ea101fa4030fa44f828fa443058badded44d0810171d721f4058307f40edd3070db3c8e8c3120d72c239b4b73a431dd70e2100f01f08ef5eda2edfb209821d7498102b2b9dcdf218308d722028308d723208020d721d34fd31fd31fed44d0d200d31f20d34fd70bff09f90140b9f910289602f26001f2a39e02945f09db31e001945f08db31e1e25122baf2a15036baf2a2f823bbf2642292f800dea470c8ca00cb1f01cf16c9ed54f80fdb3cd81002cc9401d200018edbd72c20e206dcfc2091709901d72c22f577a52412e25210b18e3b30d72c21065dcad48e2dd200ed44d0d200d31f5205953001f2ab709f02f26b01810150d721d70b00f2aa7fe2c8ca00cb1f58cf16c9ed5492f229e2e30dd74cd001e8d74c011211005021d7393020c700dc8e1ad72820761e436c20d71d06c7125220b0f265d74cd7393020c700e65bed55009001fa4001fa44f828fa443022baf2aded44d0810171d71821d70a0001f405069d3002c8ca0740148307f453f2a79e33048307f45bf2a8206e58b0f26ce2c85003cf1612f400c9ed545d9452a0"

type ConfigV5R1 struct {
	NetworkGlobalID int32
	Workchain       int8
}

type SpecV5R1 struct {
	SpecRegular
	SpecSeqno

	config ConfigV5R1
}

const MainnetGlobalID = -239
const TestnetGlobalID = -3

func (s *SpecV5R1) BuildMessage(ctx context.Context, _ bool, _ *ton.BlockIDExt, messages []*Message) (_ *cell.Cell, err error) {
	// TODO: remove block, now it is here for backwards compatibility

	if len(messages) > 255 {
		return nil, errors.New("for this type of wallet max 4 messages can be sent in the same time")
	}

	seq, err := s.seqnoFetcher(ctx, s.wallet.subwallet)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch seqno: %w", err)
	}

	actions, err := packV5Actions(messages)
	if err != nil {
		return nil, fmt.Errorf("failed to build actions: %w", err)
	}

	payload := cell.BeginCell().
		MustStoreUInt(0x7369676e, 32). // external sign op code
		MustStoreInt(int64(s.config.NetworkGlobalID), 32).
		MustStoreInt(int64(s.config.Workchain), 8).
		MustStoreUInt(0, 8). // version of v5
		MustStoreUInt(uint64(s.wallet.subwallet), 32).
		MustStoreUInt(uint64(timeNow().Add(time.Duration(s.messagesTTL)*time.Second).UTC().Unix()), 32).
		MustStoreUInt(uint64(seq), 32).
		MustStoreBuilder(actions)

	sign := payload.EndCell().Sign(s.wallet.key)
	msg := cell.BeginCell().MustStoreBuilder(payload).MustStoreSlice(sign, 512).EndCell()

	return msg, nil
}

func packV5Actions(messages []*Message) (*cell.Builder, error) {
	if len(messages) > 255 {
		return nil, fmt.Errorf("max 255 messages allowed for v5")
	}

	var list = cell.BeginCell().EndCell()
	for _, message := range messages {
		outMsg, err := tlb.ToCell(message.InternalMessage)
		if err != nil {
			return nil, err
		}

		/*
			out_list_empty$_ = OutList 0;
			out_list$_ {n:#} prev:^(OutList n) action:OutAction
			  = OutList (n + 1);
			action_send_msg#0ec3c86d mode:(## 8)
			  out_msg:^(MessageRelaxed Any) = OutAction;
		*/
		msg := cell.BeginCell().MustStoreUInt(0x0ec3c86d, 32).
			MustStoreUInt(uint64(message.Mode), 8).
			MustStoreRef(outMsg)

		list = cell.BeginCell().MustStoreRef(list).MustStoreBuilder(msg).EndCell()
	}

	return cell.BeginCell().MustStoreUInt(0, 1).MustStoreRef(list), nil
}
