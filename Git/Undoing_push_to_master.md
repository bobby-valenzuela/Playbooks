
1.	While on local master branch… undo last commit (so you can stash those changes later)
1.	 $ git reset --soft HEAD~1
2.	This undoes your last commit and moves the changes from that commit back to ‘staged’.
2.	Now that the changes from your last commit are staged again you can stash your changes
1.	$ git stash save nameofcoolstash 
2.	Your local master branch should be how it was before you made any changes.
3.	Use git pull to pull the latest push (that you pushed to master) down to your local master branch.
1.	git pull
2.	This also adds your latest commit hash into the git log (this is the commit where you pushed to master).
4.	List the log of your past commit. (Just showing last five with this code)
1.	git log –n 5 –oneline
5.	Find (and copy) the hash of the commit where you pushed to master
1.	Should be the first (most recent) commit
6.	Use git revert to undo the commit
1.	git revert <hash> --no-commit -–no-edit
2.	 
1.	–no-commit = keep reverted changes staged
2.	–no-edit = keep default commit msg
3.	This will not merely undo but rather inverse the changes you pushed to the master branch. So this is a set of changes such that your previously commit will effectively be cancelled out by these changes once you commit. 
7.	Now your local master branch will have all reverted stuff
8.	On your local master branch, stage and commit these changes.
1.	Add some msg like ‘undoing push to master’
2.	git add -A 
3.	git commit -m "Reverting push to master"
4.	git push
9.	Now, run git pull again – everything should be back the way it was
10.	Now, checkout a new branch!
11.	Unstash those changes
