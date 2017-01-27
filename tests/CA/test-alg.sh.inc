#
# Copyright (c) 2004-2015 Roumen Petrov, Sofia, Bulgaria
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
#  - "IdentityFile" contain private key and optional x509 certificate;
#  - "AuthorizedKeysFile" contain certificate BLOB.
#  - 1) server accept different publickey algorithms.
#  - 2) client use failback publickey algorithm.
# Note that "Host-Based Authentication" we can not test without to install.
#


# ===
#args:
#  $1 - identity file
fill_authorized () {
  # fill with extra host-keys to simulate multiple key-types
  cat testhostkey_*.pub > "$AUTHORIZEDKEYSFILE"

  "$TEST_SSH_SSHKEYGEN" -f "$1" -y 2>/dev/null >> "$AUTHORIZEDKEYSFILE"
}


# ===
#env. vars:
#  alg
testAlg1 () {
  printSeparator
  echo "  - only ${attn}${alg}${norm} algorithm"

  creTestSSHDcfgFile
  if test "x${SSH_X509STORE_DISABLED}" != "xyes"; then
    cat >> "$SSHD_CFG" <<EOF
CACertificateFile ${SSH_CAROOT}/${CACERTFILE}
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF
    fi
  cat >> "$SSHD_CFG" <<EOF
PubkeyAlgorithms $alg
EOF

  runSSHdaemon || return $?
  (

    for SSH_CLIENTKEY in $TEST_SSH_CLIENTKEYS ; do

      withcert=
      expr $alg : 'x509v3-' >/dev/null && withcert=yes

      # 'plain' key
      must_fail=yes
      if test -z "$withcert" ; then
        case $SSH_CLIENTKEY in
        *_rsa)  test $alg = ssh-rsa && must_fail=;;
        *_dsa)  test $alg = ssh-dss && must_fail=;;
        *_ecc*) curve=`echo $SSH_CLIENTKEY | sed 's/^.*_ecc//'`
                test $alg = ecdsa-sha2-$curve && must_fail=;;
        *)
          echo "${warn}unknown 'plain' client key type${norm}"
          exit 1;;
        esac
      fi

      identity_file="${SSH_CLIENTKEY}"
      fill_authorized "$identity_file" || exit $?

      if test -n "$must_fail"; then
        typemsg="${identity_file} ${warn}!${norm}"
      else
        typemsg="${identity_file}"
      fi
      runTest "${typemsg}" \
        "${identity_file}" "" "$must_fail" || exit $?

      # X.509 keys
      for type in $SSH_SIGN_TYPES ; do

        must_fail=yes
        if test -n "$withcert" ; then
          case $SSH_CLIENTKEY in
          *_rsa*) test $alg = x509v3-sign-rsa && must_fail=;;
          *_dsa*) test $alg = x509v3-sign-dss && must_fail=;;
          *_ecc*) curve=`echo $SSH_CLIENTKEY | sed 's/^.*_ecc//'`
                  test $alg = x509v3-ecdsa-sha2-$curve && must_fail=;;
          *)
            echo "${warn}unknown 'x.509' client key type${norm}"
            exit 1;;
          esac
        fi

        identity_file="${SSH_CLIENTKEY}-${type}"
        fill_authorized "$identity_file" || exit $?

        if test -n "$must_fail"; then
          typemsg="${identity_file} ${warn}!${norm}"
        else
          typemsg="${identity_file}"
        fi
        runTest "${typemsg}" \
          "${identity_file}" "" "$must_fail" || exit $?
      done
    done
  ); retval=$?
  killSSHdaemon

  return $retval
}


# ===
#env. vars:
#  alg - only public key based
testAlg2 () {
  printSeparator
  echo "  - client failback to ${attn}${alg}${norm} algorithm"

  # list only public key algorithms for 'plain' keys
  pkalg="ssh-rsa,ssh-dss"
  if test -n "$SSH_EC_ALGS_PLAIN" ; then
    for a in $SSH_EC_ALGS_PLAIN ; do
      pkalg="$pkalg,$a"
    done
  fi

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
CACertificateFile /file/not/found
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
PubkeyAlgorithms $pkalg
EOF

  runSSHdaemon || return $?
  (
    TEST_CLIENT_CFG="\
PubkeyAlgorithms $alg
"
    for SSH_CLIENTKEY in $TEST_SSH_CLIENTKEYS; do
      must_fail=
      case $SSH_CLIENTKEY in
      *_rsa)  test $alg = ssh-rsa || must_fail=yes;;
      *_dsa)  test $alg = ssh-dss || must_fail=yes;;
      *_ecc*) curve=`echo $SSH_CLIENTKEY | sed 's/^.*_ecc//'`
              test $alg = ecdsa-sha2-$curve || must_fail=yes;;
      *)
        echo "${warn}unknown client key type${norm}"
        exit 1;;
      esac

      identity_file="$SSH_CLIENTKEY"
      fill_authorized "$identity_file" || exit $?

      for type in $SSH_SIGN_TYPES; do
        identity_file="$SSH_CLIENTKEY-$type"

        if test -n "$must_fail"; then
          typemsg="$identity_file ${warn}!${norm}"
        else
          typemsg="$identity_file"
        fi

        runTest "$typemsg" "$identity_file" "" "$must_fail" || exit $?
      done
    done
  ); retval=$?
  killSSHdaemon

  return $retval
}


# ===
#env. vars:
#  alg
testAlg3 () {
  printSeparator
  echo "  - only ${attn}X.509${norm} algorithms"

  creTestSSHDcfgFile
  if test "x$SSH_X509STORE_DISABLED" != "xyes"; then
    cat >> "$SSHD_CFG" <<EOF
CACertificateFile $SSH_CAROOT/$CACERTFILE
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF
    fi
  cat >> "$SSHD_CFG" <<EOF
PubkeyAlgorithms x509v3-*
EOF

  runSSHdaemon || return $?
  (

    for SSH_CLIENTKEY in $TEST_SSH_CLIENTKEYS ; do

      for type in "" $SSH_SIGN_TYPES; do

        if test -z "$type" ; then
          identity_file="$SSH_CLIENTKEY"
          withcert=
          must_fail=yes
          typemsg="$identity_file ${warn}!${norm} (plain key)"
        else
          identity_file="$SSH_CLIENTKEY-$type"
          withcert=yes
          must_fail=
          typemsg="$identity_file"
        fi

        fill_authorized "$identity_file" || exit $?

        runTest "$typemsg" \
          "$identity_file" "" "$must_fail" || exit $?

      done
    done
  ); retval=$?
  killSSHdaemon

  return $retval
}


# ===

do_test () {
  retval=0
  if test "x${SSH_X509STORE_DISABLED}" = "xyes"; then
    echo "* ${extd}with different publickey ${attn}algorithms${norm}:"
  else
    echo "* ${extd}against ${attn}CACertificateFile${norm} and different publickey ${attn}algorithms${norm}:"
  fi

  for alg in \
    "ssh-rsa" \
    "ssh-dss" \
    $SSH_EC_ALGS_PLAIN \
    "x509v3-sign-rsa" \
    "x509v3-sign-dss" \
    $SSH_EC_ALGS_X509 \
  ; do
    testAlg1; retval=$?
    if test $retval -ne 0; then
      return $retval
    fi
  done

  for alg in \
    "ssh-rsa" \
    "ssh-dss" \
    $SSH_EC_ALGS_PLAIN \
  ; do
    testAlg2; retval=$?
    if test $retval -ne 0; then
      return $retval
    fi
  done

  testAlg3; retval=$?
  if test $retval -ne 0; then
    return $retval
  fi

  return 0
}
