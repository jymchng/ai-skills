#!/usr/bin/env python3
"""Framework, runtime and build-system detection (audit stage 2a).

Discovery order matters, and it is deliberate: manifests are authoritative,
lockfiles prove the resolved ecosystem, and source imports fill the gap when a
project has no manifest (a single-file Flask app, a Go service built by a
Makefile). Every detection carries the file it came from, because a technology
claim without evidence is the kind of thing that makes a report untrustworthy.

Read-only, deterministic, stdlib only. Consumes ``inventory.json`` when given
(so stage 1 does not run twice) and otherwise walks the tree itself.

Usage
-----
    python3 scripts/detect_technologies.py --root . --out technologies.json
    python3 scripts/detect_technologies.py --inventory inventory.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import repository_inventory as inv  # noqa: E402  (local sibling module)

TOOL_VERSION = "1.0.0"

try:                                    # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:             # pragma: no cover - 3.10 and older
    _toml = None


# --------------------------------------------------------------------------- #
# Dependency signature table
# --------------------------------------------------------------------------- #
#: (ecosystem, normalised dependency name) -> (display name, category).
#: Categories drive the attack-surface rule selection, so they are the point.
FRAMEWORKS: Dict[str, Dict[str, Tuple[str, str]]] = {
    "npm": {
        "express": ("Express", "web_framework"),
        "koa": ("Koa", "web_framework"),
        "fastify": ("Fastify", "web_framework"),
        "@hapi/hapi": ("hapi", "web_framework"),
        "@nestjs/core": ("NestJS", "web_framework"),
        "next": ("Next.js", "web_framework"),
        "nuxt": ("Nuxt", "web_framework"),
        "@sveltejs/kit": ("SvelteKit", "web_framework"),
        "react": ("React", "ui_framework"),
        "react-dom": ("React", "ui_framework"),
        "vue": ("Vue", "ui_framework"),
        "@angular/core": ("Angular", "ui_framework"),
        "svelte": ("Svelte", "ui_framework"),
        "sequelize": ("Sequelize", "orm"),
        "typeorm": ("TypeORM", "orm"),
        "prisma": ("Prisma", "orm"),
        "@prisma/client": ("Prisma", "orm"),
        "mongoose": ("Mongoose", "orm"),
        "knex": ("Knex", "orm"),
        "pg": ("node-postgres", "database_driver"),
        "mysql": ("mysqljs", "database_driver"),
        "mysql2": ("mysql2", "database_driver"),
        "sqlite3": ("sqlite3", "database_driver"),
        "mongodb": ("MongoDB driver", "database_driver"),
        "ioredis": ("ioredis", "cache_client"),
        "redis": ("node-redis", "cache_client"),
        "passport": ("Passport", "auth"),
        "passport-jwt": ("passport-jwt", "auth"),
        "passport-local": ("passport-local", "auth"),
        "jsonwebtoken": ("jsonwebtoken", "auth"),
        "jose": ("jose", "auth"),
        "bcrypt": ("bcrypt", "crypto"),
        "bcryptjs": ("bcryptjs", "crypto"),
        "argon2": ("argon2", "crypto"),
        "crypto-js": ("crypto-js", "crypto"),
        "next-auth": ("NextAuth", "auth"),
        "@auth/core": ("Auth.js", "auth"),
        "express-session": ("express-session", "session"),
        "cookie-session": ("cookie-session", "session"),
        "csurf": ("csurf", "security_middleware"),
        "helmet": ("Helmet", "security_middleware"),
        "cors": ("cors", "security_middleware"),
        "express-rate-limit": ("express-rate-limit", "security_middleware"),
        "graphql": ("GraphQL", "graphql"),
        "apollo-server": ("Apollo Server", "graphql"),
        "@apollo/server": ("Apollo Server", "graphql"),
        "type-graphql": ("TypeGraphQL", "graphql"),
        "socket.io": ("Socket.IO", "websocket"),
        "ws": ("ws", "websocket"),
        "@grpc/grpc-js": ("gRPC", "rpc"),
        "bull": ("Bull", "queue"),
        "bullmq": ("BullMQ", "queue"),
        "amqplib": ("amqplib", "queue"),
        "kafkajs": ("KafkaJS", "queue"),
        "aws-sdk": ("AWS SDK", "cloud_sdk"),
        "@aws-sdk/client-s3": ("AWS SDK", "cloud_sdk"),
        "stripe": ("Stripe", "payments"),
        "twilio": ("Twilio", "messaging"),
        "nodemailer": ("Nodemailer", "messaging"),
        "ejs": ("EJS", "template_engine"),
        "pug": ("Pug", "template_engine"),
        "handlebars": ("Handlebars", "template_engine"),
        "mustache": ("Mustache", "template_engine"),
        "commander": ("Commander", "cli"),
        "yargs": ("yargs", "cli"),
        "node-cron": ("node-cron", "scheduler"),
        "multer": ("Multer", "file_upload"),
        "formidable": ("Formidable", "file_upload"),
        "axios": ("Axios", "http_client"),
        "node-fetch": ("node-fetch", "http_client"),
        "got": ("got", "http_client"),
        "jest": ("Jest", "test"),
        "mocha": ("Mocha", "test"),
        "vitest": ("Vitest", "test"),
        "webpack": ("Webpack", "bundler"),
        "vite": ("Vite", "bundler"),
        "rollup": ("Rollup", "bundler"),
        "esbuild": ("esbuild", "bundler"),
        "typescript": ("TypeScript", "language_tooling"),
    },
    "pypi": {
        "django": ("Django", "web_framework"),
        "djangorestframework": ("Django REST Framework", "web_framework"),
        "flask": ("Flask", "web_framework"),
        "fastapi": ("FastAPI", "web_framework"),
        "starlette": ("Starlette", "web_framework"),
        "tornado": ("Tornado", "web_framework"),
        "aiohttp": ("aiohttp", "web_framework"),
        "sanic": ("Sanic", "web_framework"),
        "pyramid": ("Pyramid", "web_framework"),
        "bottle": ("Bottle", "web_framework"),
        "falcon": ("Falcon", "web_framework"),
        "litestar": ("Litestar", "web_framework"),
        "streamlit": ("Streamlit", "web_framework"),
        "gradio": ("Gradio", "web_framework"),
        "sqlalchemy": ("SQLAlchemy", "orm"),
        "flask-sqlalchemy": ("Flask-SQLAlchemy", "orm"),
        "peewee": ("peewee", "orm"),
        "tortoise-orm": ("Tortoise ORM", "orm"),
        "psycopg2": ("psycopg2", "database_driver"),
        "psycopg2-binary": ("psycopg2", "database_driver"),
        "psycopg": ("psycopg", "database_driver"),
        "pymysql": ("PyMySQL", "database_driver"),
        "mysqlclient": ("mysqlclient", "database_driver"),
        "pymongo": ("PyMongo", "database_driver"),
        "motor": ("Motor", "database_driver"),
        "redis": ("redis-py", "cache_client"),
        "celery": ("Celery", "queue"),
        "rq": ("RQ", "queue"),
        "dramatiq": ("Dramatiq", "queue"),
        "kombu": ("Kombu", "queue"),
        "pika": ("pika", "queue"),
        "kafka-python": ("kafka-python", "queue"),
        "confluent-kafka": ("confluent-kafka", "queue"),
        "jinja2": ("Jinja2", "template_engine"),
        "mako": ("Mako", "template_engine"),
        "pyjwt": ("PyJWT", "auth"),
        "python-jose": ("python-jose", "auth"),
        "authlib": ("Authlib", "auth"),
        "oauthlib": ("oauthlib", "auth"),
        "passlib": ("passlib", "crypto"),
        "bcrypt": ("bcrypt", "crypto"),
        "cryptography": ("cryptography", "crypto"),
        "pycryptodome": ("PyCryptodome", "crypto"),
        "itsdangerous": ("itsdangerous", "crypto"),
        "flask-login": ("Flask-Login", "auth"),
        "flask-wtf": ("Flask-WTF", "security_middleware"),
        "django-cors-headers": ("django-cors-headers", "security_middleware"),
        "django-ratelimit": ("django-ratelimit", "security_middleware"),
        "slowapi": ("slowapi", "security_middleware"),
        "graphene": ("Graphene", "graphql"),
        "strawberry-graphql": ("Strawberry", "graphql"),
        "ariadne": ("Ariadne", "graphql"),
        "websockets": ("websockets", "websocket"),
        "channels": ("Django Channels", "websocket"),
        "grpcio": ("gRPC", "rpc"),
        "boto3": ("boto3", "cloud_sdk"),
        "google-cloud-storage": ("Google Cloud Storage", "cloud_sdk"),
        "azure-storage-blob": ("Azure Blob Storage", "cloud_sdk"),
        "stripe": ("Stripe", "payments"),
        "requests": ("requests", "http_client"),
        "httpx": ("httpx", "http_client"),
        "urllib3": ("urllib3", "http_client"),
        "pyyaml": ("PyYAML", "serialisation"),
        "lxml": ("lxml", "serialisation"),
        "click": ("Click", "cli"),
        "typer": ("Typer", "cli"),
        "argparse": ("argparse", "cli"),
        "apscheduler": ("APScheduler", "scheduler"),
        "schedule": ("schedule", "scheduler"),
        "pytest": ("pytest", "test"),
        "gunicorn": ("Gunicorn", "server"),
        "uvicorn": ("Uvicorn", "server"),
        "waitress": ("Waitress", "server"),
    },
    "go": {
        "github.com/gin-gonic/gin": ("Gin", "web_framework"),
        "github.com/labstack/echo/v4": ("Echo", "web_framework"),
        "github.com/labstack/echo": ("Echo", "web_framework"),
        "github.com/go-chi/chi/v5": ("chi", "web_framework"),
        "github.com/go-chi/chi": ("chi", "web_framework"),
        "github.com/gorilla/mux": ("gorilla/mux", "web_framework"),
        "github.com/gofiber/fiber/v2": ("Fiber", "web_framework"),
        "github.com/gofiber/fiber": ("Fiber", "web_framework"),
        "net/http": ("net/http", "web_framework"),
        "github.com/beego/beego/v2": ("Beego", "web_framework"),
        "gorm.io/gorm": ("GORM", "orm"),
        "github.com/jmoiron/sqlx": ("sqlx", "orm"),
        "github.com/lib/pq": ("lib/pq", "database_driver"),
        "github.com/jackc/pgx/v5": ("pgx", "database_driver"),
        "go.mongodb.org/mongo-driver": ("mongo-go-driver", "database_driver"),
        "github.com/redis/go-redis/v9": ("go-redis", "cache_client"),
        "github.com/golang-jwt/jwt/v5": ("golang-jwt", "auth"),
        "github.com/golang-jwt/jwt/v4": ("golang-jwt", "auth"),
        "github.com/dgrijalva/jwt-go": ("jwt-go (deprecated)", "auth"),
        "golang.org/x/crypto/bcrypt": ("bcrypt", "crypto"),
        "github.com/gorilla/sessions": ("gorilla/sessions", "session"),
        "github.com/99designs/gqlgen": ("gqlgen", "graphql"),
        "github.com/graphql-go/graphql": ("graphql-go", "graphql"),
        "github.com/gorilla/websocket": ("gorilla/websocket", "websocket"),
        "google.golang.org/grpc": ("gRPC", "rpc"),
        "github.com/spf13/cobra": ("Cobra", "cli"),
        "github.com/urfave/cli/v2": ("urfave/cli", "cli"),
        "github.com/hibiken/asynq": ("Asynq", "queue"),
        "github.com/segmentio/kafka-go": ("kafka-go", "queue"),
        "github.com/aws/aws-sdk-go": ("AWS SDK", "cloud_sdk"),
        "github.com/aws/aws-sdk-go-v2": ("AWS SDK v2", "cloud_sdk"),
        "text/template": ("text/template", "template_engine"),
        "html/template": ("html/template", "template_engine"),
    },
    "rubygems": {
        "rails": ("Ruby on Rails", "web_framework"),
        "railties": ("Ruby on Rails", "web_framework"),
        "actionpack": ("Ruby on Rails", "web_framework"),
        "sinatra": ("Sinatra", "web_framework"),
        "hanami": ("Hanami", "web_framework"),
        "grape": ("Grape", "web_framework"),
        "activerecord": ("ActiveRecord", "orm"),
        "sequel": ("Sequel", "orm"),
        "pg": ("pg", "database_driver"),
        "mysql2": ("mysql2", "database_driver"),
        "sqlite3": ("sqlite3", "database_driver"),
        "mongoid": ("Mongoid", "orm"),
        "redis": ("redis-rb", "cache_client"),
        "devise": ("Devise", "auth"),
        "doorkeeper": ("Doorkeeper", "auth"),
        "jwt": ("ruby-jwt", "auth"),
        "bcrypt": ("bcrypt", "crypto"),
        "pundit": ("Pundit", "authorisation"),
        "cancancan": ("CanCanCan", "authorisation"),
        "sidekiq": ("Sidekiq", "queue"),
        "resque": ("Resque", "queue"),
        "delayed_job": ("Delayed Job", "queue"),
        "sucker_punch": ("Sucker Punch", "queue"),
        "graphql": ("GraphQL Ruby", "graphql"),
        "actioncable": ("ActionCable", "websocket"),
        "faye-websocket": ("faye-websocket", "websocket"),
        "grpc": ("gRPC", "rpc"),
        "faraday": ("Faraday", "http_client"),
        "httparty": ("HTTParty", "http_client"),
        "rack-cors": ("rack-cors", "security_middleware"),
        "rack-attack": ("Rack::Attack", "security_middleware"),
        "haml": ("Haml", "template_engine"),
        "slim": ("Slim", "template_engine"),
        "erb": ("ERB", "template_engine"),
        "thor": ("Thor", "cli"),
        "rake": ("Rake", "build"),
        "rspec": ("RSpec", "test"),
        "carrierwave": ("CarrierWave", "file_upload"),
        "shrine": ("Shrine", "file_upload"),
        "paperclip": ("Paperclip", "file_upload"),
    },
    "packagist": {
        "laravel/framework": ("Laravel", "web_framework"),
        "slim/slim": ("Slim", "web_framework"),
        "symfony/framework-bundle": ("Symfony", "web_framework"),
        "symfony/http-kernel": ("Symfony", "web_framework"),
        "cakephp/cakephp": ("CakePHP", "web_framework"),
        "yiisoft/yii2": ("Yii2", "web_framework"),
        "laminas/laminas-mvc": ("Laminas", "web_framework"),
        "doctrine/orm": ("Doctrine ORM", "orm"),
        "illuminate/database": ("Laravel Eloquent", "orm"),
        "laravel/sanctum": ("Laravel Sanctum", "auth"),
        "laravel/passport": ("Laravel Passport", "auth"),
        "firebase/php-jwt": ("firebase/php-jwt", "auth"),
        "paragonie/random_compat": ("random_compat", "crypto"),
        "defuse/php-encryption": ("php-encryption", "crypto"),
        "guzzlehttp/guzzle": ("Guzzle", "http_client"),
        "symfony/security-bundle": ("Symfony Security", "auth"),
        "spatie/laravel-permission": ("spatie/laravel-permission", "authorisation"),
        "barryvdh/laravel-cors": ("laravel-cors", "security_middleware"),
        "fruitcake/laravel-cors": ("laravel-cors", "security_middleware"),
        "twig/twig": ("Twig", "template_engine"),
        "phpunit/phpunit": ("PHPUnit", "test"),
        "webonyx/graphql-php": ("graphql-php", "graphql"),
        "pusher/pusher-php-server": ("Pusher", "websocket"),
        "symfony/console": ("Symfony Console", "cli"),
    },
    "maven": {
        "org.springframework.boot:spring-boot-starter-web": ("Spring Boot Web", "web_framework"),
        "org.springframework:spring-webmvc": ("Spring MVC", "web_framework"),
        "org.springframework.boot": ("Spring Boot", "web_framework"),
        "org.springframework:spring-core": ("Spring Framework", "web_framework"),
        "io.quarkus:quarkus-core": ("Quarkus", "web_framework"),
        "io.micronaut:micronaut-core": ("Micronaut", "web_framework"),
        "io.javalin:javalin": ("Javalin", "web_framework"),
        "org.springframework.boot:spring-boot-starter-security": ("Spring Security", "auth"),
        "org.springframework.security:spring-security-core": ("Spring Security", "auth"),
        "org.springframework.boot:spring-boot-starter-data-jpa": ("Spring Data JPA", "orm"),
        "org.hibernate:hibernate-core": ("Hibernate", "orm"),
        "org.mybatis:mybatis": ("MyBatis", "orm"),
        "org.postgresql:postgresql": ("PostgreSQL JDBC", "database_driver"),
        "mysql:mysql-connector-java": ("MySQL JDBC", "database_driver"),
        "com.mysql:mysql-connector-j": ("MySQL JDBC", "database_driver"),
        "org.mongodb:mongodb-driver-sync": ("MongoDB Java driver", "database_driver"),
        "redis.clients:jedis": ("Jedis", "cache_client"),
        "io.jsonwebtoken:jjwt": ("jjwt", "auth"),
        "com.auth0:java-jwt": ("java-jwt", "auth"),
        "org.springframework.boot:spring-boot-starter-thymeleaf": ("Thymeleaf", "template_engine"),
        "org.apache.shiro:shiro-core": ("Apache Shiro", "auth"),
        "com.graphql-java:graphql-java": ("graphql-java", "graphql"),
        "org.springframework.kafka:spring-kafka": ("Spring Kafka", "queue"),
        "org.springframework.amqp:spring-rabbit": ("Spring AMQP", "queue"),
        "com.squareup.retrofit2:retrofit": ("Retrofit", "http_client"),
        "org.apache.httpcomponents:httpclient": ("Apache HttpClient", "http_client"),
        "org.junit.jupiter:junit-jupiter": ("JUnit 5", "test"),
        "org.springframework.boot:spring-boot-starter-actuator": ("Spring Actuator", "management"),
    },
    "nuget": {
        "Microsoft.AspNetCore": ("ASP.NET Core", "web_framework"),
        "Microsoft.AspNetCore.Mvc": ("ASP.NET Core MVC", "web_framework"),
        "Microsoft.AspNetCore.App": ("ASP.NET Core", "web_framework"),
        "Microsoft.EntityFrameworkCore": ("Entity Framework Core", "orm"),
        "Dapper": ("Dapper", "orm"),
        "Npgsql": ("Npgsql", "database_driver"),
        "MySql.Data": ("MySQL Connector/NET", "database_driver"),
        "MongoDB.Driver": ("MongoDB .NET driver", "database_driver"),
        "StackExchange.Redis": ("StackExchange.Redis", "cache_client"),
        "Microsoft.AspNetCore.Authentication.JwtBearer": ("JWT Bearer auth", "auth"),
        "Microsoft.Identity.Web": ("Microsoft Identity Web", "auth"),
        "IdentityServer4": ("IdentityServer4", "auth"),
        "Duende.IdentityServer": ("Duende IdentityServer", "auth"),
        "BCrypt.Net-Next": ("BCrypt.Net", "crypto"),
        "Newtonsoft.Json": ("Newtonsoft.Json", "serialisation"),
        "System.Text.Json": ("System.Text.Json", "serialisation"),
        "AutoMapper": ("AutoMapper", "mapping"),
        "Serilog": ("Serilog", "logging"),
        "Swashbuckle.AspNetCore": ("Swashbuckle", "documentation"),
        "MediatR": ("MediatR", "architecture"),
        "xunit": ("xUnit", "test"),
        "Microsoft.AspNetCore.SignalR": ("SignalR", "websocket"),
        "Grpc.AspNetCore": ("gRPC", "rpc"),
        "Hangfire": ("Hangfire", "scheduler"),
        "RestSharp": ("RestSharp", "http_client"),
        "System.IdentityModel.Tokens.Jwt": ("JWT handler", "auth"),
        "Microsoft.AspNetCore.Identity": ("ASP.NET Identity", "auth"),
    },
    "cargo": {
        "axum": ("axum", "web_framework"),
        "actix-web": ("Actix Web", "web_framework"),
        "rocket": ("Rocket", "web_framework"),
        "warp": ("warp", "web_framework"),
        "sqlx": ("sqlx", "orm"),
        "diesel": ("Diesel", "orm"),
        "tokio-postgres": ("tokio-postgres", "database_driver"),
        "redis": ("redis-rs", "cache_client"),
        "jsonwebtoken": ("jsonwebtoken", "auth"),
        "argon2": ("argon2", "crypto"),
        "ring": ("ring", "crypto"),
        "serde_json": ("serde_json", "serialisation"),
        "reqwest": ("reqwest", "http_client"),
        "tower-http": ("tower-http", "security_middleware"),
        "clap": ("clap", "cli"),
    },
}

#: Import names that reveal a framework when no manifest lists it.
IMPORT_HINTS: Dict[str, Dict[str, Tuple[str, str]]] = {
    "python": {
        "django": ("Django", "web_framework"),
        "flask": ("Flask", "web_framework"),
        "fastapi": ("FastAPI", "web_framework"),
        "starlette": ("Starlette", "web_framework"),
        "tornado": ("Tornado", "web_framework"),
        "aiohttp": ("aiohttp", "web_framework"),
        "sqlalchemy": ("SQLAlchemy", "orm"),
        "pymongo": ("PyMongo", "database_driver"),
        "psycopg2": ("psycopg2", "database_driver"),
        "celery": ("Celery", "queue"),
        "jwt": ("PyJWT", "auth"),
        "passlib": ("passlib", "crypto"),
        "cryptography": ("cryptography", "crypto"),
        "jinja2": ("Jinja2", "template_engine"),
        "graphene": ("Graphene", "graphql"),
        "boto3": ("boto3", "cloud_sdk"),
        "requests": ("requests", "http_client"),
        "yaml": ("PyYAML", "serialisation"),
        "pickle": ("pickle", "serialisation"),
        "click": ("Click", "cli"),
        "argparse": ("argparse", "cli"),
    },
    "javascript": {
        "express": ("Express", "web_framework"),
        "koa": ("Koa", "web_framework"),
        "fastify": ("Fastify", "web_framework"),
        "@nestjs/core": ("NestJS", "web_framework"),
        "react": ("React", "ui_framework"),
        "vue": ("Vue", "ui_framework"),
        "sequelize": ("Sequelize", "orm"),
        "mongoose": ("Mongoose", "orm"),
        "jsonwebtoken": ("jsonwebtoken", "auth"),
        "passport": ("Passport", "auth"),
        "socket.io": ("Socket.IO", "websocket"),
        "ws": ("ws", "websocket"),
        "graphql": ("GraphQL", "graphql"),
        "axios": ("Axios", "http_client"),
        "child_process": ("child_process", "process_exec"),
        "helmet": ("Helmet", "security_middleware"),
    },
    "typescript": {
        "express": ("Express", "web_framework"),
        "@nestjs/core": ("NestJS", "web_framework"),
        "next": ("Next.js", "web_framework"),
        "@angular/core": ("Angular", "ui_framework"),
        "typeorm": ("TypeORM", "orm"),
        "prisma": ("Prisma", "orm"),
        "jsonwebtoken": ("jsonwebtoken", "auth"),
        "@nestjs/jwt": ("NestJS JWT", "auth"),
        "graphql": ("GraphQL", "graphql"),
    },
    "go": {
        "github.com/gin-gonic/gin": ("Gin", "web_framework"),
        "github.com/labstack/echo/v4": ("Echo", "web_framework"),
        "github.com/go-chi/chi/v5": ("chi", "web_framework"),
        "github.com/gorilla/mux": ("gorilla/mux", "web_framework"),
        "net/http": ("net/http", "web_framework"),
        "database/sql": ("database/sql", "orm"),
        "os/exec": ("os/exec", "process_exec"),
        "encoding/gob": ("encoding/gob", "serialisation"),
        "crypto/tls": ("crypto/tls", "crypto"),
    },
    "ruby": {
        "rails": ("Ruby on Rails", "web_framework"),
        "sinatra": ("Sinatra", "web_framework"),
        "active_record": ("ActiveRecord", "orm"),
        "devise": ("Devise", "auth"),
        "pundit": ("Pundit", "authorisation"),
        "sidekiq": ("Sidekiq", "queue"),
        "jwt": ("ruby-jwt", "auth"),
        "open3": ("open3", "process_exec"),
        "yaml": ("YAML", "serialisation"),
    },
    "php": {
        "illuminate": ("Laravel", "web_framework"),
        "laravel": ("Laravel", "web_framework"),
        "slim": ("Slim", "web_framework"),
        "symfony": ("Symfony", "web_framework"),
        "pdo": ("PDO", "database_driver"),
        "mysqli": ("mysqli", "database_driver"),
        "firebase": ("firebase/php-jwt", "auth"),
    },
    "java": {
        "org.springframework": ("Spring", "web_framework"),
        "jakarta.servlet": ("Jakarta Servlet", "web_framework"),
        "javax.servlet": ("Java Servlet", "web_framework"),
        "org.hibernate": ("Hibernate", "orm"),
        "java.sql": ("JDBC", "database_driver"),
        "io.jsonwebtoken": ("jjwt", "auth"),
        "org.springframework.security": ("Spring Security", "auth"),
        "java.io": ("java.io", "serialisation"),
    },
    "csharp": {
        "Microsoft.AspNetCore": ("ASP.NET Core", "web_framework"),
        "Microsoft.EntityFrameworkCore": ("Entity Framework Core", "orm"),
        "System.Data.SqlClient": ("SqlClient", "database_driver"),
        "Microsoft.Data.SqlClient": ("SqlClient", "database_driver"),
        "System.IdentityModel.Tokens.Jwt": ("JWT handler", "auth"),
        "Newtonsoft.Json": ("Newtonsoft.Json", "serialisation"),
        "System.Runtime.Serialization": ("BinaryFormatter namespace", "serialisation"),
        "System.Diagnostics.Process": ("Process", "process_exec"),
    },
}

#: Package-manager and build-system markers, by relative path or filename.
PACKAGE_MANAGER_MARKERS: Tuple[Tuple[str, str, str], ...] = (
    (r"^package-lock\.json$", "npm", "lockfile"),
    (r"^yarn\.lock$", "yarn", "lockfile"),
    (r"^pnpm-lock\.yaml$", "pnpm", "lockfile"),
    (r"^bun\.lockb$", "bun", "lockfile"),
    (r"^Pipfile(\.lock)?$", "pipenv", "lockfile"),
    (r"^poetry\.lock$", "poetry", "lockfile"),
    (r"^uv\.lock$", "uv", "lockfile"),
    (r"^requirements.*\.txt$", "pip", "requirements"),
    (r"^go\.sum$", "go modules", "lockfile"),
    (r"^Gemfile\.lock$", "bundler", "lockfile"),
    (r"^composer\.lock$", "composer", "lockfile"),
    (r"^packages\.lock\.json$", "nuget", "lockfile"),
    (r"^gradle-wrapper\.properties$", "gradle", "wrapper"),
    (r"^maven-wrapper\.properties$", "maven", "wrapper"),
    (r"^Cargo\.lock$", "cargo", "lockfile"),
    (r"^mix\.lock$", "hex", "lockfile"),
    (r"^pubspec\.lock$", "pub", "lockfile"),
    # Manifests without a lockfile still prove which manager the project uses;
    # a repository that vendors nothing and commits no lockfile is common, and
    # reporting "unknown package manager" there would be wrong.
    (r"^go\.mod$", "go modules", "manifest"),
    (r"^pom\.xml$", "maven", "manifest"),
    (r"^build\.gradle(\.kts)?$", "gradle", "manifest"),
    (r"^Gemfile$", "bundler", "manifest"),
    (r"^composer\.json$", "composer", "manifest"),
    (r"^Cargo\.toml$", "cargo", "manifest"),
    (r"\.csproj$", "nuget", "manifest"),
    (r"^pyproject\.toml$", "pip", "manifest"),
    (r"^Pipfile$", "pipenv", "manifest"),
)

BUILD_TOOLS: Tuple[Tuple[str, str], ...] = (
    (r"^Makefile$", "Make"),
    (r"^CMakeLists\.txt$", "CMake"),
    (r"^meson\.build$", "Meson"),
    (r"^BUILD(\.bazel)?$", "Bazel"),
    (r"^WORKSPACE$", "Bazel"),
    (r"^build\.gradle(\.kts)?$", "Gradle"),
    (r"^pom\.xml$", "Maven"),
    (r"^settings\.gradle(\.kts)?$", "Gradle"),
    (r"^webpack\.config\.\w+$", "Webpack"),
    (r"^vite\.config\.\w+$", "Vite"),
    (r"^rollup\.config\.\w+$", "Rollup"),
    (r"^esbuild\.config\.\w+$", "esbuild"),
    (r"^tsconfig\.json$", "TypeScript compiler"),
    (r"^babel\.config\.\w+$", "Babel"),
    (r"^\.babelrc$", "Babel"),
    (r"^justfile$", "just"),
    (r"^Taskfile\.ya?ml$", "Task"),
    (r"^noxfile\.py$", "nox"),
    (r"^tox\.ini$", "tox"),
    (r"^setup\.py$", "setuptools"),
    (r"^setup\.cfg$", "setuptools"),
    (r"^pyproject\.toml$", "PEP 517 build"),
    (r"^build\.sbt$", "sbt"),
    (r"^Package\.swift$", "SwiftPM"),
    (r"^\.goreleaser\.ya?ml$", "GoReleaser"),
    (r"^Dockerfile$", "Docker"),
    (r"^skaffold\.ya?ml$", "Skaffold"),
)

CI_MARKERS: Tuple[Tuple[str, str], ...] = (
    (r"^\.github/workflows/[^/]+\.ya?ml$", "GitHub Actions"),
    (r"^\.gitlab-ci\.yml$", "GitLab CI"),
    (r"^\.travis\.yml$", "Travis CI"),
    (r"^Jenkinsfile$", "Jenkins"),
    (r"^azure-pipelines\.yml$", "Azure Pipelines"),
    (r"^\.circleci/config\.yml$", "CircleCI"),
    (r"^bitbucket-pipelines\.yml$", "Bitbucket Pipelines"),
    (r"^\.drone\.yml$", "Drone"),
    (r"^\.buildkite/.+\.ya?ml$", "Buildkite"),
    (r"^cloudbuild\.ya?ml$", "Google Cloud Build"),
    (r"^\.github/dependabot\.ya?ml$", "Dependabot"),
    (r"^renovate\.json$", "Renovate"),
)

RUNTIME_VERSION_FILES: Tuple[Tuple[str, str], ...] = (
    (".nvmrc", "node"), (".node-version", "node"),
    (".python-version", "python"), (".ruby-version", "ruby"),
    (".tool-versions", "asdf"), (".go-version", "go"),
    (".java-version", "java"), ("global.json", "dotnet"),
)

MONOREPO_MARKERS: Tuple[Tuple[str, str], ...] = (
    (r"^pnpm-workspace\.yaml$", "pnpm workspaces"),
    (r"^lerna\.json$", "Lerna"),
    (r"^nx\.json$", "Nx"),
    (r"^turbo\.json$", "Turborepo"),
    (r"^rush\.json$", "Rush"),
    (r"^go\.work$", "Go workspaces"),
    (r"^settings\.gradle(\.kts)?$", "Gradle multi-project"),
    (r"^WORKSPACE$", "Bazel workspace"),
    (r"^Cargo\.toml$", "Cargo workspace"),
    (r"^packages/?$", "packages directory"),
    (r"^apps/?$", "apps directory"),
    (r"^services/?$", "services directory"),
    (r"^libs/?$", "libs directory"),
)

DATA_STORE_HINTS: Dict[str, str] = {
    "psycopg2": "postgresql", "psycopg": "postgresql", "pg": "postgresql",
    "pgx": "postgresql", "postgresql": "postgresql", "npgsql": "postgresql",
    "mysql": "mysql", "mysql2": "mysql", "mysqlclient": "mysql", "pymysql": "mysql",
    "mariadb": "mariadb",
    "sqlite3": "sqlite", "better-sqlite3": "sqlite",
    "mongodb": "mongodb", "pymongo": "mongodb", "mongoose": "mongodb",
    "motor": "mongodb", "mongoid": "mongodb", "mongo-driver": "mongodb",
    "redis": "redis", "ioredis": "redis", "jedis": "redis", "go-redis": "redis",
    "elasticsearch": "elasticsearch", "opensearch": "opensearch",
    "cassandra-driver": "cassandra",
    "dynamodb": "dynamodb", "@aws-sdk/client-dynamodb": "dynamodb",
    "sqlalchemy": "sql (generic)", "sequelize": "sql (generic)",
    "typeorm": "sql (generic)", "prisma": "sql (generic)",
    "hibernate-core": "sql (generic)", "entityframeworkcore": "sql (generic)",
    "gorm": "sql (generic)", "activerecord": "sql (generic)",
}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _norm(name: str) -> str:
    """Normalise a dependency name: lowercase, extras and version markers stripped.

    ``@`` and ``/`` are *not* separators: scoped npm packages (``@nestjs/core``)
    and Go/Java coordinates (``github.com/gin-gonic/gin``) depend on them, and
    splitting on ``@`` silently turned every scoped package into an empty string.
    """
    name = name.strip().strip("\"'")
    name = name.split("[")[0]
    name = re.split(r"[\s<>=!~;,(]", name)[0]
    return name.strip().lower()


def _add(bucket: Dict[str, Dict[str, Any]], name: str, category: str,
         ecosystem: str, file: str, line: Optional[int] = None,
         version: Optional[str] = None, dependency: Optional[str] = None) -> None:
    """Record one detected technology, keeping the first (strongest) evidence.

    ``dependency`` is the raw package id as written in the manifest. It is kept
    separately from ``name`` because data-store and capability inference must
    match on ids (``pg``), not display names (``node-postgres``).
    """
    key = f"{name}|{category}"
    if key in bucket:
        existing = bucket[key]
        if version and not existing.get("version"):
            existing["version"] = version
        if dependency and not existing.get("dependency"):
            existing["dependency"] = dependency
        return
    evidence: Dict[str, Any] = {"file": file}
    if line:
        evidence["line"] = line
    bucket[key] = {"name": name, "category": category, "ecosystem": ecosystem,
                   "dependency": dependency or _norm(name),
                   "version": version, "evidence": evidence}



def _lookup(table: Dict[str, Tuple[str, str]], raw: str) -> Optional[Tuple[str, str]]:
    key = _norm(raw)
    if key in table:
        return table[key]
    # Go and Java use path-like coordinates; try progressively shorter prefixes.
    parts = key.split("/")
    while len(parts) > 1:
        parts.pop()
        candidate = "/".join(parts)
        if candidate in table:
            return table[candidate]
    return None


# --------------------------------------------------------------------------- #
# Manifest parsers
# --------------------------------------------------------------------------- #

def parse_package_json(path: str, rel: str, found: Dict[str, Dict[str, Any]],
                       meta: Dict[str, Any]) -> None:
    try:
        data = json.loads(_read(path))
    except (ValueError, TypeError):
        meta.setdefault("unparsed_manifests", []).append(rel)
        return
    if not isinstance(data, dict):
        return
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, raw_version in deps.items():
            hit = _lookup(FRAMEWORKS["npm"], name)
            if hit:
                _add(found, hit[0], hit[1], "npm", rel, None, str(raw_version), _norm(name))
    if data.get("workspaces"):
        workspaces = data["workspaces"]
        if isinstance(workspaces, dict):
            workspaces = workspaces.get("packages") or []
        if isinstance(workspaces, list):
            meta.setdefault("workspace_globs", []).extend(str(w) for w in workspaces)
    if data.get("packageManager"):
        meta["package_manager_field"] = str(data["packageManager"])
    engines = data.get("engines") or {}
    if isinstance(engines, dict):
        for runtime, version in engines.items():
            meta.setdefault("engines", []).append({"runtime": runtime, "version": str(version),
                                                   "file": rel})
    if data.get("type") == "module":
        meta["module_type"] = "esm"


def parse_requirements(path: str, rel: str, found: Dict[str, Dict[str, Any]]) -> None:
    for number, raw in enumerate(_read(path).splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        name = _norm(line)
        hit = _lookup(FRAMEWORKS["pypi"], name)
        if hit:
            version = None
            match = re.search(r"[=<>!~]=?\s*([\w.*]+)", line)
            if match:
                version = match.group(1)
            _add(found, hit[0], hit[1], "pypi", rel, number, version, name)


def parse_toml_deps(path: str, rel: str, found: Dict[str, Dict[str, Any]],
                    meta: Dict[str, Any], ecosystem: str) -> None:
    if _toml is None:
        meta.setdefault("unparsed_manifests", []).append(rel)
        return
    try:
        with open(path, "rb") as handle:
            data = _toml.load(handle)
    except Exception:
        meta.setdefault("unparsed_manifests", []).append(rel)
        return
    if not isinstance(data, dict):
        return
    tables: List[Any] = [data.get("dependencies"), data.get("dev-dependencies"),
                         (data.get("project") or {}).get("dependencies") if isinstance(
                             data.get("project"), dict) else None,
                         (data.get("tool") or {}).get("poetry", {}).get("dependencies")
                         if isinstance(data.get("tool"), dict) else None,
                         (data.get("tool") or {}).get("poetry", {}).get("dev-dependencies")
                         if isinstance(data.get("tool"), dict) else None]
    for table in tables:
        if isinstance(table, dict):
            for name, value in table.items():
                hit = _lookup(FRAMEWORKS[ecosystem], name)
                if hit:
                    version = value if isinstance(value, str) else (
                        value.get("version") if isinstance(value, dict) else None)
                    _add(found, hit[0], hit[1], ecosystem, rel, None,
                         str(version) if version else None, _norm(name))
        elif isinstance(table, list):
            for entry in table:
                if isinstance(entry, str):
                    hit = _lookup(FRAMEWORKS[ecosystem], entry)
                    if hit:
                        _add(found, hit[0], hit[1], ecosystem, rel, None, None, _norm(entry))
    if isinstance(data.get("workspace"), dict):
        members = data["workspace"].get("members")
        if isinstance(members, list):
            meta.setdefault("workspace_globs", []).extend(str(m) for m in members)


def parse_go_mod(path: str, rel: str, found: Dict[str, Dict[str, Any]],
                 meta: Dict[str, Any]) -> None:
    text = _read(path)
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("go "):
            meta.setdefault("engines", []).append({"runtime": "go", "version": line[3:].strip(),
                                                   "file": rel})
        module = re.match(r"^module\s+(\S+)", line)
        if module:
            meta["module_path"] = module.group(1)
    in_block = False
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        entry = None
        if in_block:
            entry = line
        elif line.startswith("require "):
            entry = line[len("require "):].strip()
        if not entry or entry.startswith("//"):
            continue
        parts = entry.split()
        if not parts:
            continue
        hit = _lookup(FRAMEWORKS["go"], parts[0])
        if hit:
            _add(found, hit[0], hit[1], "go", rel, number,
                 parts[1] if len(parts) > 1 else None, _norm(parts[0]))


def parse_gemfile(path: str, rel: str, found: Dict[str, Dict[str, Any]]) -> None:
    for number, raw in enumerate(_read(path).splitlines(), start=1):
        match = re.search(r"""^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""", raw)
        if not match:
            continue
        hit = _lookup(FRAMEWORKS["rubygems"], match.group(1))
        if hit:
            _add(found, hit[0], hit[1], "rubygems", rel, number, match.group(2),
                 _norm(match.group(1)))


def parse_composer_json(path: str, rel: str, found: Dict[str, Dict[str, Any]]) -> None:
    try:
        data = json.loads(_read(path))
    except (ValueError, TypeError):
        return
    if not isinstance(data, dict):
        return
    for section in ("require", "require-dev"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, version in deps.items():
            hit = _lookup(FRAMEWORKS["packagist"], name)
            if hit:
                _add(found, hit[0], hit[1], "packagist", rel, None, str(version), _norm(name))


def parse_pom_xml(path: str, rel: str, found: Dict[str, Dict[str, Any]],
                  meta: Dict[str, Any]) -> None:
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError):
        meta.setdefault("unparsed_manifests", []).append(rel)
        return
    namespace = ""
    root = tree.getroot()
    if root.tag.startswith("{"):
        namespace = root.tag[:root.tag.index("}") + 1]

    def text_of(element, tag: str) -> Optional[str]:
        child = element.find(namespace + tag)
        return child.text.strip() if child is not None and child.text else None

    for dependency in root.iter(namespace + "dependency"):
        group = text_of(dependency, "groupId") or ""
        artifact = text_of(dependency, "artifactId") or ""
        version = text_of(dependency, "version")
        for candidate in (f"{group}:{artifact}", group, artifact):
            hit = FRAMEWORKS["maven"].get(candidate.lower())
            if hit:
                _add(found, hit[0], hit[1], "maven", rel, None, version, candidate)
                break
    for properties in root.iter(namespace + "properties"):
        for child in properties:
            tag = child.tag.split("}")[-1]
            if tag.endswith(".version"):
                meta.setdefault("engines", []).append(
                    {"runtime": tag.replace(".version", ""), "version": (child.text or "").strip(),
                     "file": rel})


def parse_csproj(path: str, rel: str, found: Dict[str, Dict[str, Any]],
                 meta: Dict[str, Any]) -> None:
    text = _read(path)
    for number, raw in enumerate(text.splitlines(), start=1):
        match = re.search(r'PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]+)")?', raw)
        if not match:
            continue
        hit = _lookup(FRAMEWORKS["nuget"], match.group(1))
        if hit:
            _add(found, hit[0], hit[1], "nuget", rel, number, match.group(2),
                 _norm(match.group(1)))
    for match in re.finditer(r"<TargetFramework>([^<]+)</TargetFramework>", text):
        meta.setdefault("engines", []).append({"runtime": "dotnet", "version": match.group(1),
                                               "file": rel})


def parse_gradle(path: str, rel: str, found: Dict[str, Dict[str, Any]]) -> None:
    text = _read(path)
    for number, raw in enumerate(text.splitlines(), start=1):
        match = re.search(
            r"""(?:implementation|api|compile|runtimeOnly|testImplementation)\s*\(?\s*['"]([^:'"]+):([^:'"]+)(?::([^'"]+))?['"]""",
            raw)
        if not match:
            continue
        coordinate = f"{match.group(1)}:{match.group(2)}".lower()
        hit = FRAMEWORKS["maven"].get(coordinate)
        if hit:
            _add(found, hit[0], hit[1], "gradle", rel, number, match.group(3), coordinate)


def parse_elixir(path: str, rel: str, found: Dict[str, Dict[str, Any]]) -> None:
    for match in re.finditer(r"\{:(\w+),\s*\"([^\"]+)\"", _read(path)):
        _add(found, match.group(1), "library", "hex", rel, None, match.group(2),
             match.group(1).lower())


# --------------------------------------------------------------------------- #
# Import scanning
# --------------------------------------------------------------------------- #

JS_IMPORT_RE = re.compile(r"""(?:import\s[^;]*?from\s*['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"])""")
PY_IMPORT_RE = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", re.MULTILINE)
GO_IMPORT_RE = re.compile(r'^\s*(?:import\s+)?(?:\w+\s+)?"([^"]+)"', re.MULTILINE)
RUBY_REQUIRE_RE = re.compile(r"""^\s*require\s+['"]([^'"]+)['"]""", re.MULTILINE)
PHP_USE_RE = re.compile(r"^\s*use\s+([\w\\]+)", re.MULTILINE)
JAVA_IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)", re.MULTILINE)
CS_USING_RE = re.compile(r"^\s*using\s+([\w.]+)\s*;", re.MULTILINE)


def scan_imports(rel: str, path: str, language: str,
                 found: Dict[str, Dict[str, Any]]) -> None:
    """Fill in frameworks from source imports when no manifest listed them."""
    table = IMPORT_HINTS.get(language)
    if not table:
        return
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read(400_000)
    except OSError:
        return
    names: List[str] = []
    if language in ("javascript", "typescript"):
        for match in JS_IMPORT_RE.finditer(text):
            names.append(next(group for group in match.groups() if group))
    elif language == "python":
        for match in PY_IMPORT_RE.finditer(text):
            names.append(next(group for group in match.groups() if group))
    elif language == "go":
        block = re.search(r"import\s*\((.*?)\)", text, re.DOTALL)
        if block:
            names.extend(GO_IMPORT_RE.findall(block.group(1)))
        for match in re.finditer(r'^\s*import\s+"([^"]+)"', text, re.MULTILINE):
            names.append(match.group(1))
    elif language == "ruby":
        names.extend(RUBY_REQUIRE_RE.findall(text))
    elif language == "php":
        names.extend(PHP_USE_RE.findall(text))
    elif language == "java":
        names.extend(JAVA_IMPORT_RE.findall(text))
    elif language == "csharp":
        names.extend(CS_USING_RE.findall(text))

    for raw in names:
        candidate = raw
        if language == "python":
            candidate = raw.split(".")[0]
        elif language in ("javascript", "typescript"):
            candidate = raw
        elif language == "go":
            candidate = raw
        elif language == "java":
            candidate = ".".join(raw.split(".")[:2])
        for probe in (candidate, raw, candidate.split("/")[0]):
            hit = table.get(probe.lower())
            if not hit and language == "javascript":
                hit = table.get(_norm(probe))
            if hit:
                _add(found, hit[0], hit[1], language + " (import)", rel, None, None,
                     _norm(raw))
                break


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #

def detect(root: str, inventory_doc: Optional[Dict[str, Any]] = None,
           max_import_files: int = 4000) -> Dict[str, Any]:
    root = os.path.abspath(root)
    if inventory_doc is None:
        inventory_doc = inv.inventory(root)

    files = inventory_doc.get("files", [])
    limitations: List[str] = []
    found: Dict[str, Dict[str, Any]] = {}
    meta: Dict[str, Any] = {}
    runtimes: Dict[str, Dict[str, Any]] = {}
    package_managers: Dict[str, Dict[str, Any]] = {}
    build_tools: Dict[str, Dict[str, Any]] = {}
    ci: Dict[str, Dict[str, Any]] = {}
    infra: Dict[str, Dict[str, Any]] = {}
    monorepo_markers: Dict[str, Dict[str, Any]] = {}

    def add_infra(kind: str, path: str, detail: Optional[str] = None) -> None:
        key = f"{kind}|{detail or ''}"
        if key not in infra:
            infra[key] = {"kind": kind, "path": path, "detail": detail}

    for entry in files:
        rel = entry["path"]
        path = os.path.join(root, rel)
        name = os.path.basename(rel)

        # ---- manifests ---------------------------------------------------- #
        if name == "package.json":
            parse_package_json(path, rel, found, meta)
        elif re.match(r"^requirements[^/]*\.txt$", name):
            parse_requirements(path, rel, found)
        elif name == "pyproject.toml":
            parse_toml_deps(path, rel, found, meta, "pypi")
        elif name == "Pipfile":
            parse_toml_deps(path, rel, found, meta, "pypi")
        elif name == "Cargo.toml":
            parse_toml_deps(path, rel, found, meta, "cargo")
            # A root Cargo.toml is a single crate unless it declares a
            # [workspace]; flagging every crate as a monorepo was a false signal.
            if re.search(r"^\s*\[workspace\]", _read(path), re.MULTILINE):
                monorepo_markers.setdefault("Cargo workspace",
                                            {"tool": "Cargo workspace", "file": rel})
        elif name == "go.mod":
            parse_go_mod(path, rel, found, meta)
        elif name == "go.work":
            monorepo_markers.setdefault("Go workspaces", {"tool": "Go workspaces",
                                                          "file": rel})
        elif name == "Gemfile":
            parse_gemfile(path, rel, found)
        elif name == "composer.json":
            parse_composer_json(path, rel, found)
        elif name == "pom.xml":
            parse_pom_xml(path, rel, found, meta)
        elif name.endswith(".csproj"):
            parse_csproj(path, rel, found, meta)
        elif name in ("build.gradle", "build.gradle.kts"):
            parse_gradle(path, rel, found)
        elif name == "mix.exs":
            parse_elixir(path, rel, found)

        # ---- package managers, build systems, CI, infra -------------------- #
        for pattern, manager, kind in PACKAGE_MANAGER_MARKERS:
            if re.search(pattern, name) or re.search(pattern, rel):
                package_managers.setdefault(manager, {"name": manager, "kind": kind,
                                                      "evidence": rel})
                break
        for pattern, tool in BUILD_TOOLS:
            if re.search(pattern, name):
                build_tools.setdefault(tool, {"name": tool, "evidence": rel})
                break
        for pattern, system in CI_MARKERS:
            if re.search(pattern, rel):
                ci.setdefault(system, {"name": system, "path": rel})
                break
        for pattern, tool in MONOREPO_MARKERS:
            if re.search(pattern, rel):
                monorepo_markers.setdefault(tool, {"tool": tool, "file": rel})

        bucket = entry.get("bucket")
        language = entry.get("language")
        if bucket == "iac":
            if language == "dockerfile":
                add_infra("container_image", rel)
            elif language == "terraform":
                add_infra("terraform", rel)
            elif language == "github-actions":
                add_infra("ci_workflow", rel)
            elif language == "kubernetes":
                add_infra("kubernetes_manifest", rel)
            elif re.search(r"docker-compose|compose\.ya?ml", name):
                add_infra("compose", rel)
            elif re.search(r"Chart\.yaml", name):
                add_infra("helm_chart", os.path.dirname(rel))
            elif re.search(r"\.ya?ml$", name):
                add_infra("deployment_config", rel)

        # ---- runtime version dotfiles -------------------------------------- #
        if name in dict(RUNTIME_VERSION_FILES):
            runtime = dict(RUNTIME_VERSION_FILES)[name]
            value = _read(path).strip().splitlines()
            version = value[0].strip() if value else None
            if runtime == "asdf":
                for line in value:
                    parts = line.split()
                    if len(parts) >= 2:
                        runtimes.setdefault(parts[0], {"name": parts[0], "version": parts[1],
                                                       "evidence": rel})
            else:
                runtimes.setdefault(runtime, {"name": runtime, "version": version,
                                              "evidence": rel})
        if name == "Dockerfile" or name.startswith("Dockerfile."):
            for line in _read(path).splitlines():
                match = re.match(r"\s*FROM\s+([^\s]+)", line, re.IGNORECASE)
                if match:
                    image = match.group(1)
                    base = image.split(":")[0].split("/")[-1]
                    version = image.split(":")[1] if ":" in image else None
                    runtime = {"python": "python", "node": "node", "ruby": "ruby",
                               "golang": "go", "openjdk": "java", "eclipse-temurin": "java",
                               "php": "php", "mcr.microsoft.com": "dotnet"}.get(base)
                    if runtime:
                        runtimes.setdefault(f"{runtime} (container)", {
                            "name": runtime, "version": version, "evidence": rel,
                            "source": "container_base_image"})

    # ---- imports (bounded, deterministic) ---------------------------------- #
    source_files = [entry for entry in files if entry.get("bucket") == "source"]
    if len(source_files) > max_import_files:
        limitations.append(f"import scanning limited to the first {max_import_files} of "
                           f"{len(source_files)} source files")
        source_files = source_files[:max_import_files]
    for entry in source_files:
        language = entry.get("language")
        if language in IMPORT_HINTS:
            scan_imports(entry["path"], os.path.join(root, entry["path"]), language, found)

    # ---- engines / manifests fallback ------------------------------------- #
    for engine in meta.get("engines", []):
        runtime = str(engine.get("runtime", "")).lower().lstrip("@")
        if runtime and runtime not in runtimes:
            runtimes[runtime] = {"name": runtime, "version": engine.get("version"),
                                 "evidence": engine.get("file")}
    if "node" in meta.get("module_type", "") or meta.get("module_type") == "esm":
        meta.setdefault("notes", []).append("package.json declares ESM ('type': 'module')")
    if meta.get("package_manager_field"):
        package_managers.setdefault(meta["package_manager_field"].split("@")[0],
                                    {"name": meta["package_manager_field"].split("@")[0],
                                     "kind": "declared", "evidence": "package.json"})

    source_languages = inventory_doc.get("source_languages") or []
    for row in source_languages:
        language = row["language"]
        if language in ("javascript", "typescript"):
            runtimes.setdefault("node", {"name": "node", "version": None,
                                         "evidence": "source files present"})
        elif language == "python":
            runtimes.setdefault("python", {"name": "python", "version": None,
                                           "evidence": "source files present"})
        elif language == "go":
            runtimes.setdefault("go", {"name": "go", "version": None,
                                       "evidence": "source files present"})
        elif language == "ruby":
            runtimes.setdefault("ruby", {"name": "ruby", "version": None,
                                         "evidence": "source files present"})
        elif language == "php":
            runtimes.setdefault("php", {"name": "php", "version": None,
                                        "evidence": "source files present"})
        elif language == "java":
            runtimes.setdefault("java", {"name": "java", "version": None,
                                         "evidence": "source files present"})
        elif language == "csharp":
            runtimes.setdefault("dotnet", {"name": "dotnet", "version": None,
                                           "evidence": "source files present"})

    # ---- monorepo components ---------------------------------------------- #
    components: Dict[str, Dict[str, Any]] = {}
    for entry in files:
        if entry.get("bucket") != "manifest":
            continue
        directory = os.path.dirname(entry["path"])
        if not directory:
            continue
        top = directory.split("/")[0]
        slot = components.setdefault(top, {"path": top, "manifests": []})
        slot["manifests"].append(entry["path"])
    component_rows = []
    for top in sorted(components):
        slot = components[top]
        component_rows.append({"path": slot["path"], "name": top,
                               "manifests": sorted(slot["manifests"])[:20],
                               "manifest_count": len(slot["manifests"])})
    marker_rows = sorted(monorepo_markers.values(), key=lambda row: row["tool"])
    workspace_globs = sorted(set(meta.get("workspace_globs") or []))
    # A marker (pnpm-workspace.yaml, turbo.json, [workspace]) is itself evidence
    # of a multi-package repository, so it must not be reported alongside
    # `is_monorepo: false` -- the two fields contradicting each other is worse
    # than either answer.
    is_monorepo = bool(marker_rows or workspace_globs or len(component_rows) > 1)
    if not is_monorepo:
        component_rows = []
        marker_rows = []
        workspace_globs = []

    # ---- data stores and categories --------------------------------------- #
    data_stores: Dict[str, List[str]] = {}
    for item in found.values():
        # Match on the dependency id, never the display name: "pg" is what the
        # manifest says, "node-postgres" is what we show a human.
        needle = str(item.get("dependency") or item.get("name") or "").lower()
        for hint, store in DATA_STORE_HINTS.items():
            if hint in needle:
                data_stores.setdefault(store, []).append(item["name"])
                break
    for store in data_stores:
        data_stores[store] = sorted(set(data_stores[store]))

    by_category: Dict[str, List[str]] = {}
    for item in found.values():
        by_category.setdefault(item["category"], []).append(item["name"])
    for category in by_category:
        by_category[category] = sorted(set(by_category[category]))

    frameworks = sorted(found.values(), key=lambda row: (row["category"], row["name"]))
    if not frameworks:
        limitations.append("no framework detected from manifests or imports: the attack-surface "
                           "pass will rely on generic route patterns only")
    if meta.get("unparsed_manifests"):
        limitations.append("could not parse manifest(s): " + ", ".join(
            sorted(set(meta["unparsed_manifests"]))))
    if not inventory_doc.get("git", {}).get("is_repository", False):
        limitations.append("no git metadata: detected versions describe the working tree, not a "
                           "specific commit")

    return {
        "stage": "technologies",
        "schema_version": inv.SCHEMA_VERSION,
        "tool": {"name": "detect_technologies.py", "version": TOOL_VERSION},
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "root": root,
        "snapshot": {
            "commit": inventory_doc.get("git", {}).get("commit"),
            "branch": inventory_doc.get("git", {}).get("branch"),
            "dirty": inventory_doc.get("git", {}).get("dirty"),
            "files": inventory_doc.get("totals", {}).get("files"),
        },
        "languages": source_languages,
        "runtimes": sorted(runtimes.values(), key=lambda row: row["name"]),
        "frameworks": frameworks,
        "categories": dict(sorted(by_category.items())),
        "package_managers": sorted(package_managers.values(), key=lambda row: row["name"]),
        "build_systems": sorted(build_tools.values(), key=lambda row: row["name"]),
        "ci": sorted(ci.values(), key=lambda row: row["name"]),
        "infrastructure": sorted(infra.values(), key=lambda row: (row["kind"], row["path"])),
        "monorepo": {
            "is_monorepo": is_monorepo,
            "tools": marker_rows,
            "workspace_globs": workspace_globs,
            "components": component_rows,
        },
        "data_stores": dict(sorted(data_stores.items())),
        "notes": meta.get("notes", []),
        "limitations": limitations,
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detect_technologies.py",
        description="Detect frameworks, runtimes, build systems and monorepo layout "
                    "(audit stage 2).",
        epilog="Prints JSON on stdout. Read-only.",
    )
    parser.add_argument("--root", default=".", help="repository root (default: .)")
    parser.add_argument("--inventory", help="reuse an inventory.json from stage 1")
    parser.add_argument("--out", help="write JSON here instead of stdout")
    parser.add_argument("--max-import-files", type=int, default=4000,
                        help="cap files whose imports are scanned (default 4000)")
    parser.add_argument("--indent", type=int, default=2, help="JSON indent (default 2)")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    inventory_doc = None
    if args.inventory:
        with open(args.inventory, encoding="utf-8") as handle:
            inventory_doc = json.load(handle)
        root = args.root if args.root != "." else inventory_doc.get("root", ".")
    else:
        root = args.root
    document = detect(root, inventory_doc, max(0, args.max_import_files))
    text = json.dumps(document, indent=args.indent, ensure_ascii=False) + "\n"
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(json.dumps({"written": args.out,
                          "frameworks": [f["name"] for f in document["frameworks"]],
                          "runtimes": [r["name"] for r in document["runtimes"]]}))
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
