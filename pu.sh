set -e
#shows all tags as if they were versions
git --no-pager tag --sort=version:refname --list 'v*'
#This tells Git: "Push my current branch commits like normal, and if there are any annotated tags associated with the commits I am pushing, send those up too." Either way, git push --tags is perfectly fine for your first tag push to get it out there!
#Note: this non-anotateg tag won't be pushed: git tag v0.0.1
#      but this will be: git tag -a v0.0.1 -m "Release v0.0.1"
git push --follow-tags
#push all other ones too (the lightweight tags)
git push --tags
echo done
