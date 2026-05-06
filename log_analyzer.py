with open(log_file, "r") as f:
    f.seek(0, 2)  # move to end of file

    while True:
        line = f.readline()

        if not line:
            time.sleep(1)
            continue

# RULE 1: Failed login detection
        if "Failed password" in line:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            user_match = re.search(r"for (\w+)", line)

            if ip_match:
                ip = ip_match.group(1)
                failed_attempts[ip] += 1

                if user_match:
                    user_targets[ip].add(user_match.group(1))

                count = failed_attempts[ip]
                users = len(user_targets[ip])

                if count >= 5:
                    severity = "HIGH"
                elif count >= 3:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                print(f"[{severity}] Failed login from {ip}")
                print(f"  Attempts: {count} | Users targeted: {users}\n")

        # RULE 2: Successful login after failures
        if "Accepted password" in line:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

            if ip_match:
                ip = ip_match.group(1)

                if failed_attempts[ip] >= 3:
                    print(f"[CRITICAL] Successful login AFTER failures from {ip}")
                    print("  Possible account compromise!\n")
