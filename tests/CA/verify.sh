#! /bin/sh
# Copyright (c) 2002-2015 Roumen Petrov, Sofia, Bulgaria
# All rights reserved.
#
# Redistribution and use of this script, with or without modification, is
# permitted provided that the following conditions are met:
#
# 1. Redistributions of this script must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
#  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
#  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
#  EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
#  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
#  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# DESCRIPTION: Verify all testid_*.crt testhostkey_*.crt files in current
# directory agains "Test CA".
#

CWD=`pwd`
SCRIPTDIR=`echo $0 | sed 's/verify.sh//'`
. "${SCRIPTDIR}functions"
. "${SCRIPTDIR}config"


for VERIFY in \
  "$OPENSSL verify -CAfile $SSH_CAROOT/$CACERTFILE" \
  "$OPENSSL verify -CApath $SSH_CACERTDIR" \
; do
  echo ${attn}$VERIFY ....${norm}
  for F in \
    testid_*.crt \
    testhostkey_*.crt \
    testocsp_*.crt \
  ; do
    $VERIFY "$F" || exit 1
  done
done
