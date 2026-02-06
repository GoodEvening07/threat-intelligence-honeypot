import re
from collections import Counter
from datetime import datetime

# This function reads and extracts data from the 'attacks.log' file. If the file is not found then it stops the script and gives an error message.
def parsingLogFile(logFile='logs/attacks.log'):
    try:
        with open(logFile, 'r') as l:
            logs = l.readlines()
    except FileNotFoundError:
        print(f"Major Error: {logFile} not found :^(")
        return None
    
    attacks = []
    for line in logs:
        timestapMatch = re.search(r'\[(.*?)\]', line)
        ipMatch = re.search(r'IP: ([\d.]+)', line)
        usernameMatch = re.search(r'Username: (\S+)', line)
        passwordMatch = re.search(r'Password: (\S+)', line)
        botMatch = re.search(r'Bot: (\w+)', line)

        # If all data found, then makes a small dictionary similar to a mini database entry
        if all([timestapMatch, ipMatch, usernameMatch, passwordMatch]):
            attackL = {
                'Timestamp': timestapMatch.group(1),
                'IP': ipMatch.group(1),
                'Username': usernameMatch.group(1),
                'Password': passwordMatch.group(1),
                'IsBot': botMatch.group(1) == 'True' if botMatch else False
            }
            attacks.append(attackL)
    return attacks

def printStats(attacks):
    if not attacks:
        print("No attacks were found in the log file...great")
        return

    print("\n" + "="*60)
    print("!----- Honeypot Attack Analysis -----!")
    print("="*60)

    print(f"\nTotal Login Attempts: {len(attacks)}")

    ips = [a['IP'] for a in attacks]
    uniqueIps = set(ips)
    print(f"Unique IP addresses: {len(uniqueIps)}")

    botCount = sum(1 for a in attacks if a['IsBot'])
    print(f"Bot Attempts: {botCount} ({botCount/len(attacks)*100:.1f}%)")

    timeStamps = [datetime.strptime(a['Timestamp'], '%Y-%m-%d %H:%M:%S') for a in attacks]
    print(f"-First Attack: {min(timeStamps).strftime('%Y-%m-%d %H:%M')}")
    print(f"-Last Attack: {max(timeStamps).strftime('%Y-%m-%d %H:%M')}")

    print("\n" + "-"*60)
    print("!----- Top 10 Most Active IPs -----!")
    print("-"*60)

    ipCounter = Counter(ips)
    for ip, count in ipCounter.most_common(10):
        print(f"    {ip:20s} - {count:4d} attempts")

    print("\n" + "-"*60)
    print("!----- Top 10 Most Tried Username -----!")
    print("-"*60)

    username = [a['Username'] for a in attacks]
    usernameCounter = Counter(username)
    for username, count in usernameCounter.most_common(10):
        print(f"    {username:20s} - {count:4d} attempts")

    print("\n" + "-"*60)
    print("!----- Top 10 Most Tried Passwords -----!")
    print("-"*60)
    passwords = [a['Password'] for a in attacks]
    passwordCounter = Counter(passwords)
    for passwords, count in passwordCounter.most_common(10):
        maskedPassword = passwords[:3] + '*' * max(0, len(passwords) - 3)
        print(f"    {maskedPassword:15s} - {count:4d} attempts")
    
    print("\n" + "-"*60)
    print("!----- Top 10 Username:Password Combinations -----!")
    print("-"*60)

    credentials = [(a['Username'], a['Password']) for a in attacks]
    credentialsCounter = Counter(credentials)
    for (user, pw), count in credentialsCounter.most_common(10):
        maskedPassword = pw[:3] + '*' * max(0, len(pw) - 3)
        print(f"    {user:15s} : {maskedPassword:15s} - {count:4d} attempts")

    print("\n" + "-"*60)
    print("!----- Attack By Hour of Day -----!")
    print("-"*60)

    hours = [datetime.strptime(a['Timestamp'], '%Y-%m-%d %H:%M:%S').hour for a in attacks]
    hoursCounter = Counter(hours)
    for hour in range(24):
        count = hoursCounter.get(hour, 0)
        bar = '█' * (count // max(1, max(hoursCounter.values()) // 40))
        print(f"    {hour:02d}:00 - {count:4d} {bar}")

    print("\n" + "="*60 + "\n")

def exportToCsv(attacks, outputFile='attacksAnalysis.csv'):
    import csv
    
    with open(outputFile, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['Timestamp', 'IP', 'Username', 'Password', 'IsBot'])
        writer.writeheader()
        writer.writerows(attacks)

    print(f"Data exported to {outputFile}")

def main():
    attacks = parsingLogFile()

    if attacks:
        printStats(attacks)

        export = input("Export data to CSV? (y/n): ").strip().lower()
        if export == 'y':
            exportToCsv(attacks)

if __name__ == "__main__":
    main()
