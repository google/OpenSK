#!/bin/bash
# Copyright 2019 Google LLC
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

generate_crypto_materials () {
  # OpenSK AAGUID
  local aaguid_file=crypto_data/aaguid.txt

  # Root CA key pair and certificate
  local ca_priv_key=crypto_data/opensk_ca.key
  local ca_cert_name=crypto_data/opensk_ca

  # Attestation key pair and certificate that will be embedded into the
  # firmware. The certificate will be signed by the Root CA.
  local opensk_key=crypto_data/opensk.key
  local opensk_cert_name=crypto_data/opensk_cert

  # The upgrade private key is used for signing, the corresponding public key
  # will be COSE encoded and embedded into the firmware.
  local opensk_upgrade=crypto_data/opensk_upgrade.key
  local opensk_upgrade_pub=crypto_data/opensk_upgrade_pub.pem

  # Allow invoker to override the command with a full path.
  local openssl=${OPENSSL:-$(which openssl)}

  # We need openssl command to continue
  if [ ! -x "${openssl}" ]
  then
    echo "Missing openssl command. Try to specify its full path using OPENSSL environment variable."
    exit 1
  fi

  # Exit on first error
  set -e

  force_generate="$1"
  mkdir -p crypto_data
  if [ ! -f "${ca_priv_key}" ]
  then
    "${openssl}" ecparam -genkey -name prime256v1 -out "${ca_priv_key}"
  fi

  if [ ! -f "${ca_cert_name}.pem" ]
  then
    "${openssl}" req \
      -new \
      -key "${ca_priv_key}" \
      -out "${ca_cert_name}.csr" \
      -subj "/CN=OpenSK CA"
    "${openssl}" x509 \
      -trustout \
      -req \
      -days 7305 \
      -in "${ca_cert_name}.csr" \
      -signkey "${ca_priv_key}" \
      -outform pem \
      -out "${ca_cert_name}.pem" \
      -sha256
  fi

  if [ "${force_generate}" = "Y" -o ! -f "${opensk_key}" ]
  then
    "${openssl}" ecparam -genkey -name prime256v1 -out "${opensk_key}"
  fi

  if [ "${force_generate}" = "Y" -o ! -f "${opensk_cert_name}.pem" ]
  then
    "${openssl}" req \
      -new \
      -key "${opensk_key}" \
      -out "${opensk_cert_name}.csr" \
      -subj "/CN=OpenSK Hacker Edition"
    "${openssl}" x509 \
      -req \
      -days 3652 \
      -in "${opensk_cert_name}.csr" \
      -CA "${ca_cert_name}.pem" \
      -CAkey "${ca_priv_key}" \
      -CAcreateserial \
      -outform pem \
      -out "${opensk_cert_name}.pem" \
      -sha256
  fi

  if [ "${force_generate}" = "Y" -o ! -f "${opensk_upgrade}" ]
  then
    "${openssl}" ecparam -genkey -name prime256v1 -out "${opensk_upgrade}"
    rm -f "${opensk_upgrade_pub}"
  fi

  if [ "${force_generate}" = "Y" -o ! -f "${opensk_upgrade_pub}" ]
  then
    "${openssl}" ec -in "${opensk_upgrade}" -pubout -out "${opensk_upgrade_pub}"
  fi

  if [ "${force_generate}" = "Y" -o ! -f "${aaguid_file}" ]
  then
    uuidgen > "${aaguid_file}"
  fi
}

generate_crypto_materials "$1"
