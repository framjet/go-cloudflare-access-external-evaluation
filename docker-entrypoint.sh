#!/busybox/sh
set -e

# Directory for temporary key storage
TMP_DIR="/tmp/keys"
mkdir -p "$TMP_DIR"

# Check if PUBLIC_KEY and PRIVATE_KEY are missing
if [[ -z "$PUBLIC_KEY" || -z "$PRIVATE_KEY" ]]; then
    echo "PUBLIC_KEY or PRIVATE_KEY missing. Generating new keys..."

    # Generate a new RSA key pair
    openssl genrsa -out "$TMP_DIR/private.pem" 2048 > /dev/null 2>&1
    openssl rsa -in "$TMP_DIR/private.pem" -pubout -out "$TMP_DIR/public.pem" > /dev/null 2>&1

    # Read and export the keys
    export PRIVATE_KEY="$TMP_DIR/private.pem"
    export PUBLIC_KEY="$TMP_DIR/public.pem"

    echo "Keys generated and stored in environment variables."
fi

# Execute the container's main process (CMD)
exec "$@"