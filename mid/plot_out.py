user = {}
time = []
now = 0
recordtime = 90

with open('logfile.txt', 'r+') as f:
    con = f.readline()
    while con and now < recordtime:
        data = con.split("\n")[0]
        if data[0] == "S":
            data=data[9:].split("\t")
            userKey = data[0]
            total = eval(data[1][2:])['total'][0]
            if userKey not in user:
                user[userKey] = [0]*recordtime
            user[userKey][now] = total
        elif data[0] == "R":
            pass
        else:
            now = eval(data)
            time.append(eval(data))
        con = f.readline()

for i in user:
    print(f"{i}:{user[i]}")




import matplotlib.pyplot as plt
keys = list(user.keys())
values = list(user.values())
for i in range(len(keys)):
    y_values = values[i][:recordtime]
    x_values = list(range(1, recordtime+1))
    label = keys[i]
    plt.plot(x_values, y_values, label=label)
plt.legend()
plt.xlabel('時間(sec)')
plt.ylabel('數量')
plt.title('進入的封包')
plt.show()

