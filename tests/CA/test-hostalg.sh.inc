#
# Copyright (c) 2012-2015 Roumen Petrov, Sofia, Bulgaria
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
# DESCRIPTION: Test client authentication:
#  - "IdentityFile" contain private key and optional X.509 certificate;
#  - "AuthorizedKeysFile" contain encoded client public key;
#  - user "KnownHostsFile" contain records for each host key;
#  - client accept certain hostkey algorithm.
#


USERKNOWNHOSTSFILE="$USERDIR/known_hosts-HostsTests"
for RSA_DGST in $SSH_SIGN_TYPES; do
  # get first key rsa....
  break
done


# ===

HOSTKEYtestBREAK() {
  echo
  rm -f $USERKNOWNHOSTSFILE
  rm -f $SSHD_CFG.tmp
  testBREAK
}

trap HOSTKEYtestBREAK INT QUIT ABRT KILL TERM || exit 1


# ===

do_test () {
  echo "* with ${extd}different ${attn}hostkey${norm} algorithms:"

  creTestSSHDcfgFile

  if test yes != "$SSH_X509STORE_DISABLED"; then
    cat >> "$SSHD_CFG" <<EOF
CACertificateFile $SSH_CAROOT/$CACERTFILE
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF
  fi

  mv $SSHD_CFG $SSHD_CFG.tmp
  grep -v HostKey $SSHD_CFG.tmp > $SSHD_CFG
  rm $SSHD_CFG.tmp

  cat >> "$SSHD_CFG" <<EOF
# ssh-rsa
HostKey "$CWD/testhostkey_rsa"
# ssh-dsa
HostKey "$CWD/testhostkey_dsa"
# x509v3-sign-rsa
HostKey "$CWD/testhostkey_rsa-$RSA_DGST"
# x509v3-sign-dss
HostKey "$CWD/testhostkey_dsa-dsa"
# x509v3-ecdsa-sha2-* (RFC6187)
EOF
(
  for alg in $SSH_EC_ALGS_X509 ; do
    case $alg in
    x509v3-ecdsa-sha2-*)
      curve=`echo $alg | sed 's/^.*ecdsa-sha2-//'`
      hostkey=ecc$curve-$RSA_DGST
      echo HostKey "\"$CWD/testhostkey_$hostkey\""
      ;;
    esac
  done
) >> "$SSHD_CFG"

  runSSHdaemon || return $?
  (
    identity_file="testid_rsa-$RSA_DGST"
    "$TEST_SSH_SSHKEYGEN" -f "$identity_file" -y 2>/dev/null > "$AUTHORIZEDKEYSFILE" || exit $?

    printSeparator
    echo "  - with ${attn}same public${norm} identity in known hosts file:"

    for alg in \
      x509v3-sign-rsa \
      x509v3-sign-dss \
      $SSH_EC_ALGS_X509 \
      ssh-rsa \
      ssh-dss \
      $SSH_EC_ALGS_PLAIN \
    ; do

      case $alg in
      x509v3-sign-rsa) hostkey=rsa-$RSA_DGST;;
      x509v3-sign-dss) hostkey=dsa-dsa;;
      x509v3-ecdsa-sha2-*)
                       curve=`echo $alg | sed 's/^.*ecdsa-sha2-//'`
                       hostkey=ecc$curve-$RSA_DGST;;
      ssh-rsa)         hostkey=rsa;;
      ssh-dss)         hostkey=dsa;;
      ecdsa-sha2-*)    curve=`echo $alg | sed 's/^.*ecdsa-sha2-//'`
                       hostkey=ecc$curve;;
      *)
        echo "${warn}unsupported public key algorithm : $alg${norm}"
        exit 1;;
      esac

      cat > $USERKNOWNHOSTSFILE <<EOF
[$SSHD_LISTENADDRESS]:$SSHD_PORT `cat "$CWD"/testhostkey_$hostkey.pub`
EOF

      TEST_CLIENT_CFG="\
HostKeyAlgorithms $alg
"

      typemsg="$alg"
      infomsg=".../testhostkey_$hostkey.pub"
      mustfail=no
      errmsg=
      case $alg in
      ecdsa-sha2-*)
        # hostkey aliases are not supported yet
        infomsg="${warn}!${norm} $infomsg"
        mustfail=yes
        #errmsg="no hostkey alg" before OpenSSH 6.8
        errmsg="no matching host key type found"
        ;;
      esac

      runTest "$typemsg" "$identity_file" "$infomsg" $mustfail "$errmsg" || exit $?

    done
    rm -f $USERKNOWNHOSTSFILE

exit 0
    # reserved for future use ... (hostkey aliases)

    printSeparator
    echo "  - with ${attn}public key${norm} in known hosts file:"
    #TODO
    rm -f $USERKNOWNHOSTSFILE

    printSeparator
    echo "  - with ${attn}X.509 certificate${norm} in known hosts file:"
    #TODO
    rm -f $USERKNOWNHOSTSFILE

    printSeparator
    echo "  - with ${attn}X.509 distinguished name${norm} in known hosts file:"
    #TODO
    rm -f $USERKNOWNHOSTSFILE

  ); retval=$?
  killSSHdaemon

  return $retval
}
