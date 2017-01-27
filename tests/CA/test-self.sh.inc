#
# Copyright (c) 2006-2015 Roumen Petrov, Sofia, Bulgaria
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
#  - "IdentityFile" contain private key and self-signed x509 certificate;
#  - "AuthorizedKeysFile" contain encoded either public key or X.509
#   certificate or certificate DN.
#


# ===
#args:
#  $1 - request to fail flag for encoded identity
#  $2 - request to fail flag for DN
test_self() {

  case $1 in
    Y|y|Yes|yes|YES|1)
      encoded_fail=yes;;
    *)
      encoded_fail=no;;
  esac
  case $2 in
    Y|y|Yes|yes|YES|1)
      dn_msg="${warn}DN${norm}";;
    *)
      dn_msg="${extd}DN${norm}";;
  esac

  for keytype in rsa dsa; do
    SSH_CLIENTKEY="selfid_${keytype}"

    for type in ${SSH_SIGN_TYPES}; do
      case $keytype in
        rsa)
          case $type in
            *dsa*) continue;;
          esac
          ;;
        dsa)
          case $type in
            *rsa*) continue;;
          esac
          ;;
      esac

      identity_file="${SSH_CLIENTKEY}-${type}"

      # public key
      if test yes = $encoded_fail; then
        blob_msg="encoded ${warn}public${norm} key"
      else
        blob_msg="encoded ${extd}public${norm} key"
      fi
      cat "$SSH_CLIENTKEY.pub" > "$AUTHORIZEDKEYSFILE" &&
      runTest '' "$identity_file" "$type $blob_msg" $encoded_fail \
      || return $?

      # X.509 certificate
      if test yes = $encoded_fail; then
        blob_msg="encoded ${warn}X.509${norm} certificate"
      else
        blob_msg="encoded ${extd}X.509${norm} certificate"
      fi
      cat "$identity_file.pub" > "$AUTHORIZEDKEYSFILE" &&
      runTest '' "$identity_file" "$type $blob_msg" $encoded_fail \
      || return $?

      # X.509 certificate distinguished name
      sshkeytype=`getSSHkeyType "$identity_file"` || return $?
      subject=`getSubject "$identity_file"` || return $?

      echo "$sshkeytype Subject: $subject" > "$AUTHORIZEDKEYSFILE" &&
      runTest '' "$identity_file" "$type $dn_msg" "$2" \
      || return $?
    done
  done
}

# ===

test_store () {
  retval=0
  echo "  - ${attn}with${norm} self-signed trusted by ${extd}x509store${norm}:"
  printSeparator

  cat selfid_*.crt > $CWD/selfid-bundle

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
AllowedCertPurpose skip
KeyAllowSelfIssued no
CACertificateFile $CWD/selfid-bundle
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
  (
    test_self "no" "no"
  ); retval=$?
  killSSHdaemon
  rm -f $CWD/selfid-bundle
  return $retval
}

# ===

test_pkey_no () {
  retval=0
  echo "  - ${attn}without${norm} self-signed allowed by encoded ${extd}public identity${norm}:"
  printSeparator

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
AllowedCertPurpose skip
KeyAllowSelfIssued no
CACertificateFile /file/not/found
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
  (
    test_self "yes" "yes"
  ); retval=$?
  killSSHdaemon
  return $retval
}

# ===

test_pkey_yes () {
  retval=0
  echo "  - ${attn}with${norm} self-signed allowed by encoded ${extd}public identity${norm}:"
  printSeparator

  # check if exist X.509 verification bug
  # (see mail thread "1.0.2beta2 and X.509 certificate verification")
  # expected if only
  # 'error 18 at 0 depth lookup:self signed certificate'
  # buggy if return extra:
  # 'error 20 at 0 depth lookup:unable to get local issuer certificate'
  if $OPENSSL verify "$SSH_CACERTDIR"/"$CAKEY_PREFIX"-root0.crt.pem | grep 'error 20' > /dev/null ; then
    echo "${warn}skipped due to openssl verification bug${norm}" >&2
    echo "(see email thread ${attn}1.0.2beta2 and X.509 certificate verification${norm})" >&2
    return 0
  fi

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
AllowedCertPurpose skip
KeyAllowSelfIssued yes
CACertificateFile /file/not/found
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
  (
    test_self "no" "yes"
  ); retval=$?
  killSSHdaemon
  return $retval
}

# ===

test_pkey () {
  retval=0
  echo "  - ${attn}with${norm} self-signed allowed by encoded ${extd}public identity${norm}:"
  printSeparator

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
AllowedCertPurpose skip
#Unsupported options:
#KeyAllowSelfIssued no
#CACertificateFile /file/not/found
#CACertificatePath /path/not/found
#CARevocationFile  /crlfile/not/found
#CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
  (
    test_self "no" "yes"
  ); retval=$?
  killSSHdaemon
  return $retval
}

# ===
SELFtestBREAK() {
  echo
  rm -f $CWD/selfid-bundle
  testBREAK
}

trap SELFtestBREAK INT QUIT ABRT KILL TERM || exit 1


# ===

do_test () {
  echo "* ${extd}self-signed${norm}:"
  if test yes = "$SSH_X509STORE_DISABLED"; then
    echo "  X.509 store is ${attn}disabled${norm}"
    test_pkey
  else
    test_store &&
    test_pkey_no &&
    test_pkey_yes
  fi
}
