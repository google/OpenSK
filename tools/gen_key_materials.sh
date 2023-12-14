#!/bin/bash
# Copyright 2019-2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

generate_pki () {
  # Curve parameters
  local ecparams_file=crypto_data/ecparams.pem
  # OpenSK AAGUID
  local aaguid_file=crypto_data/aaguid.txt

  # Root CA key pair and certificate
  local ca_priv_key=crypto_data/ca/root-ca/private/root-ca.key
  local ca_cert_name=crypto_data/ca/root-ca

  # Signing CA key pair and certificate
  local signing_ca_priv_key=crypto_data/ca/signing-ca/private/signing-ca.key
  local signing_ca_cert_name=crypto_data/ca/signing-ca

  # The upgrade private key is used for signing, the corresponding public key
  # will be COSE encoded and embedded into the firmware.
  local opensk_upgrade=crypto_data/opensk_upgrade.key
  local opensk_upgrade_pub=crypto_data/opensk_upgrade_pub.pem

  # Allow invoker to override the command with a full path.
  local openssl=${OPENSSL:-$(which openssl)}

  # Print version for debug purposes
  ${openssl} version

  # We need openssl command to continue
  if [ ! -x "${openssl}" ]
  then
    echo "Missing openssl command. Try to specify its full path using OPENSSL environment variable."
    exit 1
  fi

  # Exit on first error
  set -e

  force_generate="$1"
  ask_for_password="$2"

  if [ "${force_generate}" = "Y" ]
  then
    # Remove old OpenSK certs and CRL
    rm -rf crypto_data/crl crypto_data/certs
  fi

  openssl_keypwd="-nodes"
  openssl_batch="-batch"
  if [ "${ask_for_password}" = "Y" ]
  then
    openssl_keypwd=""
    openssl_batch=""
  fi

  # Create PKI directories
  mkdir -p crypto_data/ca/root-ca/private crypto_data/ca/root-ca/db
  mkdir -p crypto_data/ca/signing-ca/private crypto_data/ca/signing-ca/db
  mkdir -p crypto_data/crl crypto_data/certs
  chmod 700 crypto_data/ca/root-ca/private crypto_data/ca/signing-ca/private

  # Prepare PKI databases
  for fname in \
    crypto_data/ca/root-ca/db/root-ca.db \
    crypto_data/ca/root-ca/db/root-ca.db.attr \
    crypto_data/ca/signing-ca/db/signing-ca.db \
    crypto_data/ca/signing-ca/db/signing-ca.db.attr
  do
    if [ "${force_generate}" = "Y" -o ! -f "${fname}" ]
    then
      cp /dev/null "${fname}"
    fi
  done

  # Initialize PKI serial numbers
  for fname in \
    crypto_data/ca/root-ca/db/root-ca.pem.srl \
    crypto_data/ca/root-ca/db/root-ca.pem.srl \
    crypto_data/ca/signing-ca/db/signing-ca.pem.srl \
    crypto_data/ca/signing-ca/db/signing-ca.pem.srl
  do
    if [ "${force_generate}" = "Y" -o ! -f "${fname}" ]
    then
      echo 01 > "${fname}"
    fi
  done

  # Generate AAGUID
  if [ "${force_generate}" = "Y" -o ! -f "${aaguid_file}" ]
  then
    uuidgen > "${aaguid_file}"
  fi

  if [ ! -f "${ecparams_file}" ]
  then
    "${openssl}" ecparam -param_enc "named_curve" -name "prime256v1" -out "${ecparams_file}"
  fi

  if [ "${force_generate}" = "Y" -o ! -f "${ca_cert_name}.pem" ]
  then
    # Create root CA request and key pair
    "${openssl}" req \
      -new \
      -config tools/openssl/root-ca.conf \
      -out "${ca_cert_name}.csr" \
      -keyout "${ca_priv_key}" \
      "${openssl_keypwd}" \
      "${openssl_batch}" \
      -newkey "ec:${ecparams_file}"
    
    # Make root CA certificate
    "${openssl}" ca \
      -selfsign \
      -config tools/openssl/root-ca.conf \
      "${openssl_batch}" \
      -in "${ca_cert_name}.csr" \
      -out "${ca_cert_name}.pem" \
      -extensions root_ca_ext
  fi

  if [ "${force_generate}" = "Y" -o ! -f "${signing_ca_cert_name}.pem" ]
  then
    # Create signing CA request
    "${openssl}" req \
      -new \
      -config tools/openssl/signing-ca.conf \
      -out "${signing_ca_cert_name}.csr" \
      -keyout "${signing_ca_priv_key}" \
      "${openssl_keypwd}" \
      "${openssl_batch}" \
      -newkey "ec:${ecparams_file}"

    # Make signing CA certificate
    "${openssl}" ca \
      -config tools/openssl/root-ca.conf \
      "${openssl_batch}" \
      -in "${signing_ca_cert_name}.csr" \
      -out "${signing_ca_cert_name}.pem" \
      -extensions signing_ca_ext
  fi

  # Create firmware update key pair
  if [ "${force_generate}" = "Y" -o ! -f "${opensk_upgrade}" ]
  then
    "${openssl}" ecparam -genkey -name prime256v1 -out "${opensk_upgrade}"
    rm -f "${opensk_upgrade_pub}"
  fi

  if [ "${force_generate}" = "Y" -o ! -f "${opensk_upgrade_pub}" ]
  then
    "${openssl}" ec -in "${opensk_upgrade}" -pubout -out "${opensk_upgrade_pub}"
  fi
}

generate_new_batch () {
  local openssl=${OPENSSL:-$(which openssl)}
  # Curve parameters
  local ecparams_file=crypto_data/ecparams.pem
  # OpenSK AAGUID
  local aaguid_file=crypto_data/aaguid.txt

  set -e

  # We need openssl command to continue
  if [ ! -x "${openssl}" ]
  then
    echo "Missing openssl command. Try to specify its full path using OPENSSL environment variable."
    exit 1
  fi

  if [ ! -f "${ecparams_file}" ]
  then
    echo "Missing curve parameters. Has the PKI been generated?"
    exit 1
  fi

  if [ ! -f "${aaguid_file}" ]
  then
    echo "Missing AAGUID file."
    exit 1
  fi

  batch_id=$(uuidgen | tr -d '-')
  aaguid=$(tr -d '-' < "${aaguid_file}")

  # Attestation key pair and certificate that will be embedded into the
  # firmware. The certificate will be signed by the Root CA.
  local opensk_key=certs/${batch_id}.key
  local opensk_cert_name=certs/${batch_id}

  # x509v3 extension values are passed through environment variables.
  export OPENSK_AAGUID="${aaguid}"
  # Comma separated values of supported transport for the batch attestation certificate.
  # 0=BTC, 1=BLE, 2=USB, 3=NFC
  # Default to USB only
  export OPENSK_TRANSPORT="${OPENSK_TRANSPORT:-2}"  # comma separated values. 1=BLE, 2=USB, 3=NFC

  ask_for_password="$1"  
  openssl_keypwd="-nodes"
  openssl_batch="-batch"
  if [ "${ask_for_password}" = "Y" ]
  then
    openssl_keypwd=""
    openssl_batch=""
  fi

  # Generate certificate request for the current batch
  "${openssl}" req \
    -new \
    -config "tools/openssl/opensk.conf" \
    -keyout "crypto_data/${opensk_key}" \
    -out "crypto_data/${opensk_cert_name}.csr" \
    "${openssl_keypwd}" \
    "${openssl_batch}" \
    -newkey "ec:${ecparams_file}"
  # Sign it using signing-CA and injecting the AAGUID as an extension
  "${openssl}" ca \
    -config "tools/openssl/signing-ca.conf" \
    "${openssl_batch}" \
    -in "crypto_data/${opensk_cert_name}.csr" \
    -out "crypto_data/${opensk_cert_name}.pem" \
    -extensions "fido_key_ext"

  # Force symlink to the latest batch
  ln -s -f "${opensk_cert_name}.pem" crypto_data/opensk_cert.pem
  ln -s -f "${opensk_key}" crypto_data/opensk.key
}

if [ "X${1}" != "X" ]
then
  ask_for_password=${2:-N}
  generate_pki $1 $ask_for_password
  if [ "$1" = "Y" -o ! -f "crypto_data/opensk.key" -o ! -f "crypto_data/opensk_cert.pem" ]
  then
    generate_new_batch $ask_for_password
  fi
fi
