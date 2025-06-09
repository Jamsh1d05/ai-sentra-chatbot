import redis

redis_client = redis.Redis(host="localhost", port=6379, db=0)

name = input("Enter your name:")
redis_client.set("user_name", name)

retrieved_name = redis_client.get("user_name").decode("utf-8")

print(f"Stored name : {retrieved_name}")

