#!/bin/bash
set -e

TAG="${1:-$(git describe --tags --abbrev=0)}"
REPO="unstableneutron/webauthn-assert"
POLL_INTERVAL=10

echo "Polling release workflow for tag: $TAG"
echo "Repository: $REPO"
echo ""

# Wait for workflow to appear
echo "Waiting for workflow run to start..."
while true; do
  RUN_ID=$(gh run list --repo "$REPO" --branch "$TAG" --workflow release.yml --limit 1 --json databaseId,headBranch -q ".[] | select(.headBranch == \"$TAG\") | .databaseId" 2>/dev/null || echo "")
  
  if [ -n "$RUN_ID" ]; then
    echo "Found workflow run: $RUN_ID"
    break
  fi
  
  sleep 3
done

echo ""
echo "Watching workflow progress..."
echo "---"

while true; do
  STATUS=$(gh run view "$RUN_ID" --repo "$REPO" --json status,conclusion,jobs -q '{status: .status, conclusion: .conclusion, jobs: [.jobs[] | {name: .name, status: .status, conclusion: .conclusion}]}')
  
  WORKFLOW_STATUS=$(echo "$STATUS" | jq -r '.status')
  WORKFLOW_CONCLUSION=$(echo "$STATUS" | jq -r '.conclusion')
  
  # Clear and print current status
  echo -e "\033[2J\033[H"
  echo "Release workflow for $TAG"
  echo "Status: $WORKFLOW_STATUS | Conclusion: $WORKFLOW_CONCLUSION"
  echo "---"
  echo "$STATUS" | jq -r '.jobs[] | "\(.status | if . == "completed" then "✓" elif . == "in_progress" then "⏳" else "○" end) \(.name): \(.conclusion // .status)"'
  echo "---"
  echo "Run URL: https://github.com/$REPO/actions/runs/$RUN_ID"
  
  if [ "$WORKFLOW_STATUS" = "completed" ]; then
    echo ""
    if [ "$WORKFLOW_CONCLUSION" = "success" ]; then
      echo "✅ Release workflow completed successfully!"
      echo ""
      echo "Release assets: https://github.com/$REPO/releases/tag/$TAG"
      exit 0
    else
      echo "❌ Release workflow failed: $WORKFLOW_CONCLUSION"
      exit 1
    fi
  fi
  
  sleep "$POLL_INTERVAL"
done
