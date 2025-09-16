CC = g++
CFLAGS = -Wall -g -std=c++17 -I/usr/local/include -L/usr/local/lib

SRCS = main.cpp
OBJS = $(SRCS:.cpp=.o)

TARGET = password_generator

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ -lsodium -lpqxx -lpq

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)