#!/bin/bash

# Variables
# Used to launch the docker service  on the server, notice that we send only the build image to the server in .tar format
IMAGE_NAME="passkey-rp-server"
REMOTE_PATH="/root/docker-images"

# Se déplacer dans le dossier où l'image a été envoyée
cd $REMOTE_PATH

# Supprimer le conteneur existant (s'il existe)
docker stop $IMAGE_NAME || true
docker rm $IMAGE_NAME || true

# Supprimer l'image Docker existante (si présente)
docker rmi $IMAGE_NAME:latest || true

# Charger l'image Docker à partir du fichier tar
docker load -i ${IMAGE_NAME}.tar

echo "Docker image $IMAGE_NAME successfully loaded."
echo "Starting Docker container $IMAGE_NAME..."

# Démarrer le conteneur Docker
docker run -p 8080:8080 -e DB_HOST=172.17.152.3 -e DB_PORT=3306 -e DB_USER=ldiaks01 -e DB_PASS=aD7sgT212#^# -e REDIS_HOST=172.17.152.3 -e REDIS_PORT=6379 --add-host=database:172.17.152.3 --name $IMAGE_NAME $IMAGE_NAME:latest

# Supprimer le fichier tar après le chargement
#rm ${IMAGE_NAME}.tar

echo "Docker container $IMAGE_NAME successfully started."
