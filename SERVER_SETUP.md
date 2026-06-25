# Server Setup

Server:

```text
root@100.84.97.118
```

Do not paste the root password into commands or repo files. Type it only when
SSH prompts.

## 1. SSH In

```bash
ssh root@100.84.97.118
```

## 2. Install Build Tools

Ubuntu/Debian:

```bash
apt-get update
apt-get install -y git cmake build-essential rsync sqlite3
```

## 3. Pull Code

Fresh clone:

```bash
cd ~
git clone https://github.com/Nhatcao1/he_profiler.git
cd he_profiler
```

Existing clone:

```bash
cd ~/he_profiler
git pull
```

## 4. Build Server

Use this if OpenFHE is installed and discoverable by CMake:

```bash
cmake -S server -B server/build -DHE_PROFILER_WITH_OPENFHE=ON
cmake --build server/build
```

If CMake cannot find OpenFHE, pass `OpenFHE_DIR`.

Example:

```bash
cmake -S server -B server/build \
  -DHE_PROFILER_WITH_OPENFHE=ON \
  -DOpenFHE_DIR=/usr/local/lib/cmake/OpenFHE

cmake --build server/build
```

If `~/openfhe-development` is only a source/build tree beside `~/he_profiler`,
that is fine, but `find_package(OpenFHE)` still needs the generated or installed
OpenFHE CMake config. Locate it with:

```bash
find ~/openfhe-development -name 'OpenFHEConfig.cmake' -print
```

Then pass the folder containing that file:

```bash
cmake -S server -B server/build \
  -DHE_PROFILER_WITH_OPENFHE=ON \
  -DOpenFHE_DIR=/path/that/contains/OpenFHEConfig.cmake
```

## 5. Prepare Runtime Folders

```bash
mkdir -p server/incoming server/outgoing server/db
```

## 6. Generate Demo Directory DB

```bash
python3 server/src/build_company_directory_db.py \
  --out server/db/company_directory.sqlite
```

## 7. Run Server Evaluator

After the client sends artifacts into `server/incoming/`:

```bash
server/build/run_lut_server \
  --incoming server/incoming \
  --outgoing server/outgoing
```

The server should print fingerprints for:

```text
context.bin
refresh_key.bin
switch_key.bin
request_ct.bin
response_ct.bin
```

Use those to confirm the server is reading the exact artifacts the client sent.
