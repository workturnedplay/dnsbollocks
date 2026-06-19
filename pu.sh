
#This tells Git: "Push my current branch commits like normal, and if there are any annotated tags associated with the commits I am pushing, send those up too." Either way, git push --tags is perfectly fine for your first tag push to get it out there!
git push --follow-tags
echo done
