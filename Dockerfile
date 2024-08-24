# Étape 1 : Utiliser l'image Go pour construire l'application
FROM golang:alpine AS build

# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code. Note the slash at the end, as explained in
# https://docs.docker.com/reference/dockerfile/#copy
COPY . .

ENV REDIS_HOST=172.17.152.3
ENV REDIS_PORT=6379
ENV DB_HOST=172.17.152.3
ENV DB_PORT=3306
ENV DB_USER=ldiaks01
ENV DB_PASS=aD7sgT212#^#
# Build
RUN go build -o go_server
# Compiler l'application
# Étape 2 : Utiliser une image de base pour exécuter l'application
FROM alpine:latest

# Copier le binaire de l'étape de construction
COPY --from=build /app/go_server /go_server

# Exposer le port sur lequel l'application écoutera
EXPOSE 8080

# Lancer l'application
CMD ["/go_server"]