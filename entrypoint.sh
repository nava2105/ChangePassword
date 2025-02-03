#!/bin/sh
echo "Waiting for MySQL to be ready..."
while ! nc -z mysql 3306; do
  sleep 2
done
echo "MySQL is up - starting application..."
exec java -jar /app/app.jar
