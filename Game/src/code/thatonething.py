import os

# Replace "path\to\your_exe.exe" with the actual path to your exe file
exe_path = "dist\CyberOffensive.exe"

# Number of times to run the exe
num_runs = 5

for _ in range(num_runs):
  try:

    os.startfile(exe_path)

  except FileNotFoundError:
    print(f"Error: Exe not found at {exe_path}")

print(f"Successfully ran {exe_path} {num_runs} times (assuming no errors).")