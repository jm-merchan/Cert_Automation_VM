# Vault Secret Inventory App (Go)

Aplicacion web en Go para inventariado de secretos estaticos en Vault, con UI tipo consola de operaciones:

- Descubrimiento por namespace.
- Descubrimiento de mounts KV (v1 y v2).
- Recorrido recursivo de estructuras de secretos.
- Tabla con metadatos (incluyendo custom metadata owner/email/app).
- Colores por antiguedad de modificacion (por defecto: naranja 30 min, rojo 60 min, resto verde).
- API HTTP para consumo externo.
- Webhook de alertas cuando un secreto supera el umbral rojo.
- Procesamiento de eventos de Vault en tiempo real (topic configurable, por defecto `kv*`).
- Integracion con Vault mediante periodic token usando SDK oficial.

## Requisitos

- Go 1.23+
- Conectividad con Vault
- Token con permisos para listar namespaces, mounts y leer metadata de KV

## Ejecutar

1. Instala dependencias:

   go mod tidy

2. Inicia la aplicacion:

   go run .

3. Abre:

   http://localhost:8080

## Endpoints API

- `GET /api/health`
- `GET /api/config`
- `POST /api/config`
- `POST /api/scan`
- `GET /api/namespaces`
- `GET /api/secrets?namespace=<ns>`
- `GET /api/alerts`
- `GET /api/events`

## Campos de pantalla inicial

- Vault Address
- Periodic Token
- Namespace Origen
- Umbral Naranja (min)
- Umbral Rojo (min)
- URL Webhook Alertas
- Intervalo Escaneo (segundos)
- Topic de Eventos (ej: `kv*`, `kv-v2/data-write`)
- Filtro de Eventos (expresion opcional de Vault)

## Permisos recomendados para eventos

El token periodic debe tener permiso sobre `sys/events/subscribe/*` ademas de los paths KV y namespace necesarios para el inventario.
