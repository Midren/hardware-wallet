/*
 * This file is part of the Skycoin project, https://skycoin.net/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 * Copyright (C) 2018-2019 Skycoin Project
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <inttypes.h>

#include "tiny-firmware/firmware/layout2.h"
#include "tiny-firmware/firmware/messages.h"
#include "tiny-firmware/firmware/protect.h"
#include "tiny-firmware/firmware/gettext.h"

#include "tiny-firmware/firmware/fsm.h"
#include "tiny-firmware/firmware/fsm_impl.h"
#include "tiny-firmware/firmware/fsm_bitcoin_impl.h"

extern uint8_t msg_resp[MSG_OUT_SIZE] __attribute__((aligned));

void fsm_msgBitcoinAddress(BitcoinAddress *msg) {
    MessageType msgtype = MessageType_MessageType_SkycoinAddress;
    RESP_INIT(ResponseSkycoinAddress);
    char *failMsg = NULL;
    ErrCode_t err = msgBitcoinAddressImpl(msg, resp);
    switch (err) {
        case ErrUserConfirmation:
            layoutAddress(resp->addresses[0]);
            if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
                err = ErrActionCancelled;
                break;
            }
            // fall through
        case ErrOk:
            msg_write(MessageType_MessageType_ResponseSkycoinAddress, resp);
            layoutHome();
            return;
        case ErrPinRequired:
            failMsg = _("Expected pin");
            break;
        case ErrTooManyAddresses:
            failMsg = _("Asking for too much addresses");
            break;
        case ErrMnemonicRequired:
            failMsg = _("Mnemonic required");
            break;
        case ErrAddressGeneration:
            failMsg = _("Key pair generation failed");
            break;
        default:
            break;
    }
    fsm_sendResponseFromErrCode(err, NULL, failMsg, &msgtype);
    layoutHome();
}
