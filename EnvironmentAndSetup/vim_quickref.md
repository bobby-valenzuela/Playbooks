# Vim: Quick Reference
There are loads of good vim cheat sheets out there and this isn't a substitution, but rather a list of common/handy ones I've found to be efficient on my workflow.  
[Ultimate Cheat Sheet](https://catswhocode.com/vim-cheat-sheet)

<br />

---  

### Copy/Pasting
`reg`    - View registers 
`0p`     - Paste from 0 register   
`C-r0`  - Paste from 0 register into vim command line. (Useful for pasting into a search regex)  
`C-rw`  - Copy whatever word is under cursot and paste into vim command line. (Useful for pasting into a search regex)  
`"_dd`  - Delete line and yank to black hole register (keeps registers the same).

<br />

---

### RegEx && Searching
`\r`                - This represents newline  
`%s/(foo)/\1\r`     - Replaces matches with itself followed by a newline   

<br />

---  

### Numbers
`C-a`    - Increment Highlighted Numbers  
`GC-a`   - Increment Highlight Numbers in sequence (each matched item will increment one more than previous match).  
`C-x`    - Decrement Highlighted Numbers  
`GC-x`   - Decrement Highlight Numbers in sequence (each matched item will increment one more than previous match).

<br />

---  

### Indenting
`=` - Auto-Indenting (based on rules - works on selected text as well)  
`=ap` -  Auto-Indent Paragraph  
`<` - Indent Left  
`>` - Indent Right  

<br />

---  

### Continguous Lines of text (paragraph)
`yap` - Yank with newlines  
`yip` - Yank without newlines  
`cap` - Change with newlines  
`cip` - Change without newlines  
`dap` - Delete with newlines  
`dip` - Delete without newlines  

<br />

---  

### Brackets && Braces

##### Before brackets
`v%` - Select Content within parens/brackets (inclusively) if you're right before a bracket.  

<br />

##### Within Brackets
Finding begin/end of curly braces you're inside of...  
`vi{` - Selects everything within the block... then Esc to leave you at ending "}  
`ci{` - Change text inside brackets (exclusively)  
`ca{` - Change text inside brackets (inclusively)  
`yi{` - Yank text inside brackets (inclusively)  
`ya{` - Yank text inside brackets (exclusively)  
`di{` - Delete text inside brackets (inclusively)  
`da{` - Delete text inside brackets (exclusively)  

<br />

---  

Note: `C-` should be taken to mean `Ctrl+`. All other keys are to be entered in succession (not simultaneously).


