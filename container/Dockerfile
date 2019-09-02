# Use an official Python runtime as a parent image
FROM solanav/mubuntu:base

# Set the working directory to /app
WORKDIR /app

#RUN apt-get update && apt-get install openvpn -y

# Copy the current directory contents into the container at /app
COPY files/* /app/

# Run app.py when the container launches
CMD ["./start.sh"]
