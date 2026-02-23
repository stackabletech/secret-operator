#!/usr/bin/env bash
set -euo pipefail

MESSAGE="# Managed by .scripts\/release_cert-tools.sh"

BUMPED_VERSION=$(git-cliff --config rust/cert-tools/cliff.toml --bumped-version)
CLEANED_BUMPED_VERSION=${BUMPED_VERSION#boil-}

RELEASE_BRANCH="chore/cert-tools-release-$CLEANED_BUMPED_VERSION"

echo "Checking if working directory is clean"
if ! git diff-index --quiet HEAD --; then
  echo "Working directory is dirty, aborting" >&2
  exit 1
fi

# Prompt the user to confirm their Git identity used to create the commit
GIT_EMAIL=$(git config --includes --get user.email)
GIT_USER=$(git config --includes --get user.name)

echo "The following Git user will be used: $GIT_USER <$GIT_EMAIL>"
echo "Is this correct (Y/n)?"
read -r RESPONSE

if [[ "$RESPONSE" == "y" || "$RESPONSE" == "Y" || -z "$RESPONSE" ]]; then
  echo "Proceeding with $GIT_USER <$GIT_EMAIL>"
else
  >&2 echo "User not accepted. Exiting."
  exit 1
fi

# Check dependencies
gh auth status
git-cliff --version

# Switch to main branch after we validated that the working directory is clean
git switch main

# Make sure we have the latest remote changes locally
git pull

echo "Creating and switching to $RELEASE_BRANCH branch"
git switch -c "$RELEASE_BRANCH"

echo "Generating updated changelog for $BUMPED_VERSION"
git-cliff --config rust/cert-tools/cliff.toml --tag "$BUMPED_VERSION" > rust/cert-tools/CHANGELOG.md

echo "Updating the version to $CLEANED_BUMPED_VERSION in the Cargo.toml file"
sed -E -i "s/^version = .* $MESSAGE$/version = \"$CLEANED_BUMPED_VERSION\" $MESSAGE/" rust/cert-tools/Cargo.toml
cargo check

echo "Committing changes"
# Make sure that there are changes to be committed
if git diff-index --quiet HEAD --; then
  echo "No changes to commit"
  exit 1
fi

git add rust/cert-tools/CHANGELOG.md rust/cert-tools/Cargo.*
git commit --message "chore(cert-tools): Release $CLEANED_BUMPED_VERSION" --no-verify --gpg-sign

echo "Do you want to proceed with rasing a PR (y/N)?"
read -r RESPONSE

if [[ "$RESPONSE" == "y" || "$RESPONSE" == "Y" ]]; then
  echo "Pushing changes and raising PR"
else
  >&2 echo "Not pushing. Exiting."
  exit 1
fi

CHANGELOG_SUMMARY=$(git-cliff --config rust/cert-tools/cliff.toml --tag "$BUMPED_VERSION" --strip header --unreleased)
PR_BODY=$(mktemp)
echo -e "This PR was raised automatically by a release script. It releases $BUMPED_VERSION:\n$CHANGELOG_SUMMARY" > "$PR_BODY"

git push --set-upstream origin "$RELEASE_BRANCH"
gh pr create --base main \
  --title "chore(cert-tools): Release $CLEANED_BUMPED_VERSION" \
  --body-file "$PR_BODY" \
  --assignee "@me" \
  --draft

echo "After merging the PR, make sure to run the following commands to finish up the release:"
echo "git switch main && git pull"
echo "git tag $BUMPED_VERSION -m $BUMPED_VERSION -s"
echo "git push --follow-tags"
