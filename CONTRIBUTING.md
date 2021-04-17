If you want to contribute to the aioimaplib library don't hesitate to make pull requests. 

Here is a checklist to answer before pushing a new PR:

- Are the [automated tests](README.rst) passing ? (*to avoid to break the code*)
- Is the new feature/bugfix you're adding unit tested ? (*to avoid new code to be broken*)
- Are the commits fine grain splitted with one intent for each commit ?
  - Are my refactorings (rename, dead code, extract method, extract class...) kept separated ? (*to favor distinct discussions on opiniated changes*)
  - Is my PR containing a single feature or refactoring ? (*to allow cherry-pick or revert*)
- Is each of my tests in the same commit of the code it is related to ? (*to make a revert easier and make relationship between a test and its specific code easier to spot*)
- Do the functions in production code (aioimaplib.py) have typehints ? (*to spot type mistakes and add more autocompletion*)
