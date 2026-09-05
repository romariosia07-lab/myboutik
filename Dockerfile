# Render n'a pas de runtime PHP natif (seulement Docker, Node, Python,
# Ruby, Go, Rust, Elixir) - ce Dockerfile fournit PHP + l'extension
# PostgreSQL (pdo_pgsql, absente de l'image de base) pour executer index.php
# exactement comme en local (meme commande que router.php / Procfile).
FROM php:8.3-cli

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq-dev \
    && docker-php-ext-install pdo pdo_pgsql \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Render fournit $PORT au conteneur au demarrage ; la forme shell du CMD est
# necessaire pour que cette variable soit substituee (la forme exec ne fait
# pas d'expansion de variables).
CMD ["sh", "-c", "php -S 0.0.0.0:$PORT router.php"]
