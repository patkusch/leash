"""Planted leaks and harmless lookalikes, written as the 'don't ask again' rules they would become.

Fake values are built when the benchmark runs, so the repo never holds a string shaped like a real
token. {pw} is a made-up password; {gh}, {ant}, {aws}, {slack}, {stripe}, {whsec}, {npm}, {hf}, {gl} and {jwt}
become fake provider tokens of the right shape.
"""

# (category, command) that MUST be caught
PLANTED = [
    # the three shapes that beat gitleaks and TruffleHog in the Apiiro set
    ("env var before command", "PGPASSWORD={pw} psql -h db.internal -U app -c 'select 1'"),
    ("env var before command", "MYSQL_PWD={pw} mysql -u root app"),
    ("env var before command", "export GITHUB_TOKEN={pw}{pw} && gh pr list"),
    ("env var before command", "DB_PASSWORD={pw} npm run migrate"),
    ("env var before command", "AWS_SECRET_ACCESS_KEY={pw}{pw} aws s3 ls"),
    ("sshpass", "sshpass -p {pw} ssh deploy@10.0.0.7 'systemctl restart app'"),
    ("sshpass", "sshpass -p '{pw}' scp build.tgz deploy@10.0.0.7:/srv"),
    ("mysql -p", "mysql -u root -p{pw} app -e 'show tables'"),
    ("mysql -p", "mysqldump -uroot -p{pw} app > dump.sql"),
    # options and tool-specific flags
    ("password option", "app-cli login --password {pw}"),
    ("password option", "app-cli login --password={pw}"),
    ("password option", "twine upload --password {pw} dist/*"),
    ("password option", "deploy --api-key {pw}{pw}"),
    ("tool flag", "redis-cli -h cache.internal -a {pw} ping"),
    ("tool flag", "sqlcmd -S db.internal -U sa -P {pw} -Q 'select 1'"),
    ("tool flag", "docker login registry.example.com -u ci -p {pw}"),
    ("tool flag", "openssl pkcs12 -in cert.p12 -passin pass:{pw} -nodes"),
    # URLs, connection strings, headers
    ("password in URL", "psql postgres://app:{pw}@db.internal:5432/app"),
    ("password in URL", "mongosh 'mongodb+srv://admin:{pw}@cluster0.example.net/test'"),
    ("password in URL", "git clone https://ci:{pw}@git.example.com/team/repo.git"),
    ("connection string", "psql 'host=db.internal user=app password={pw} dbname=app'"),
    ("header", "curl -H 'Authorization: Bearer {pw}{pw}' https://api.example.com/v1/me"),
    ("header", "curl -H 'X-Api-Key: {pw}{pw}' https://api.example.com/v1/items"),
    ("curl -u", "curl -u admin:{pw} https://jenkins.internal/api/json"),
    # provider-shaped tokens (what the mainstream scanners already catch)
    ("provider token", "gh api user -H 'Authorization: token {gh}'"),
    ("provider token", "curl https://api.anthropic.com/v1/messages -H 'x-api-key: {ant}'"),
    ("provider token", "aws configure set aws_access_key_id {aws}"),
    ("provider token", "curl -X POST -H 'Authorization: Bearer {slack}' https://slack.com/api/chat.postMessage"),
    ("provider token", "stripe charges list --api-key {stripe}"),
    ("provider token", "stripe listen --forward-to localhost:3000 --skip-verify # secret {whsec}"),
    ("provider token", "npm config set //registry.npmjs.org/:_authToken {npm}"),
    ("provider token", "huggingface-cli login --token {hf}"),
    ("provider token", "glab auth login --token {gl}"),
    ("provider token", "curl -H 'Cookie: session={jwt}' https://app.example.com/admin"),
]

# commands that look close but hold no secret, and MUST NOT be flagged
BENIGN = [
    "PGPASSWORD=$PGPASSWORD psql -h db.internal -U app",
    "PGPASSWORD=\"${DB_PASS}\" psql -h db.internal",
    "mysql -u root -p app",
    "mysql -u root -p -e 'show databases'",
    "sshpass -e ssh deploy@10.0.0.7",
    "ssh -p 2222 deploy@10.0.0.7",
    "docker run -p 8080:80 nginx:1.27",
    "docker run -e DB_PASSWORD=$DB_PASSWORD app:1.0",
    "docker login registry.example.com -u ci --password-stdin",
    "redis-cli -h cache.internal ping",
    "app-cli login --password-file ~/.config/app/pw",
    "app-cli login --password $APP_PASSWORD",
    "app-cli login --token <your-token>",
    "curl -u $USER:$PASS https://jenkins.internal/api/json",
    "curl -H \"Authorization: Bearer $TOKEN\" https://api.example.com/v1/me",
    "psql postgres://app@db.internal:5432/app",
    "git clone https://git.example.com/team/repo.git",
    "git commit -m 'fix password reset email'",
    "git log --grep token",
    "grep -rn PASSWORD src/",
    "pytest -k test_token_refresh",
    "npm test -- --testNamePattern=password",
    "echo $SECRET_KEY | wc -c",
    "export GITHUB_TOKEN=$(gh auth token)",
    "openssl pkcs12 -in cert.p12 -passin env:P12_PASS -nodes",
    "sqlcmd -S db.internal -E -Q 'select 1'",
    "kubectl get secret app -o jsonpath='{.data.password}'",
    "aws secretsmanager get-secret-value --secret-id prod/db",
    "terraform apply -var-file=prod.tfvars",
    "ls -la ~/.ssh",
    "python -m pytest tests/test_auth.py",
    "make deploy ENV=staging",
    "ANTHROPIC_API_KEY=dummy-key-for-tests python3 eval/run.py",
    "API_TOKEN=fake_token_123 pytest tests/",
]
