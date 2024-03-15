solved by makider https://github.com/N1kkogg

challenge:
[main.py](./main.py)

this was a python jail escape challenge

basically your input was evaluated by removing these chars in the blacklist
```python
blacklist = [ ';', '"', 'os', '_', '\\', '/', '`',
              ' ', '-', '!', '[', ']', '*', 'import',
              'eval', 'banner', 'echo', 'cat', '%', 
              '&', '>', '<', '+', '1', '2', '3', '4',
              '5', '6', '7', '8', '9', '0', 'b', 's', 
              'lower', 'upper', 'system', '}', '{' ]

while True:
  ans = input('Break me, shake me!\n\n$ ').strip()
  
  if any(char in ans for char in blacklist):
    print(f'\n{banner1}\nNaughty naughty..\n')
  else:
    try:
      print("DEBUG: {}".format(ans))
      eval(ans + '()')
      print('WHAT WAS THAT?!\n')
```

as you can see the input is then evaluated after adding () 

here's the solution:

print(open('flag.txt','r').read()),print