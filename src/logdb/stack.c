#include <logdb/stack.h>

/**
 * "Join two stacks together."
 * 
 * The function takes two stacks as arguments. If the first stack is empty, it returns the second
 * stack. If the second stack is empty, it returns the first stack. Otherwise, it joins the second
 * stack to the end of the first stack
 * 
 * @param stack1 The first stack to join.
 * @param stack2 The stack to be joined to stack1.
 * 
 * @return The stack that is the result of the join.
 */
stk_stack *StackJoin(stk_stack *stack1, stk_stack *stack2) {
  if (!stack1->tail) {
    free(stack1);
    return (stack2);
  } else {
    stack1->tail->next = stack2->top;
    stack1->tail = stack2->tail;
    free(stack2);
    return (stack1);
  }
}

/**
 * Create a new stack
 * 
 * @return A pointer to a new stack.
 */
stk_stack *StackCreate() {
  stk_stack *newStack;

  newStack = (stk_stack *)SafeMalloc(sizeof(stk_stack));
  newStack->top = newStack->tail = NULL;
  return (newStack);
}

/**
 * Push a new node onto the stack
 * 
 * @param theStack the stack to push onto
 * @param newInfoPointer the new information to be pushed onto the stack
 */
void StackPush(stk_stack *theStack, DATA_TYPE newInfoPointer) {
  stk_stack_node *newNode;

  if (!theStack->top) {
    newNode = (stk_stack_node *)SafeMalloc(sizeof(stk_stack_node));
    newNode->info = newInfoPointer;
    newNode->next = theStack->top;
    theStack->top = newNode;
    theStack->tail = newNode;
  } else {
    newNode = (stk_stack_node *)SafeMalloc(sizeof(stk_stack_node));
    newNode->info = newInfoPointer;
    newNode->next = theStack->top;
    theStack->top = newNode;
  }
}

/**
 * Pop the top element off the stack and return its value
 * 
 * @param theStack The stack to pop from.
 * 
 * @return The value of the top of the stack.
 */
DATA_TYPE StackPop(stk_stack *theStack) {
  DATA_TYPE popInfo;
  stk_stack_node *oldNode;

  if (theStack->top) {
    popInfo = theStack->top->info;
    oldNode = theStack->top;
    theStack->top = theStack->top->next;
    free(oldNode);
    if (!theStack->top)
      theStack->tail = NULL;
  } else {
    popInfo = NULL;
  }
  return (popInfo);
}

/**
 * Destroy the stack by calling the DestFunc on each node in the stack and then free the stack
 * 
 * @param theStack The stack to be destroyed.
 * @param DestFunc The function to call when a node is removed from the stack.
 */
void StackDestroy(stk_stack *theStack, void DestFunc(void *a)) {
  stk_stack_node *x = theStack->top;
  stk_stack_node *y;

  if (theStack) {
    while (x) {
      y = x->next;
      DestFunc(x->info);
      free(x);
      x = y;
    }
    free(theStack);
  }
}
