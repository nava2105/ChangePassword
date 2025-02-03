# Use an official OpenJDK runtime as a parent image
FROM openjdk:17-jdk-slim

# Install netcat (nc) for waiting MySQL to be ready
RUN apt-get update && apt-get install -y netcat && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the built application JAR file and the entrypoint script
COPY target/Spring-Security-JWT-0.0.1-SNAPSHOT.jar app.jar
COPY entrypoint.sh /entrypoint.sh
COPY .env .env

# Give execution permissions to the script
RUN chmod +x /entrypoint.sh

# Expose the application port
EXPOSE 8078

# Use the entrypoint script
ENTRYPOINT ["/entrypoint.sh"]
