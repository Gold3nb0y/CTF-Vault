//! Intrusive singly-linked list

use core::{marker::PhantomData, ops::Try, ptr::NonNull};

/// Head of a singly-linked list.
///
/// The head itself is not considered part of the list.
pub struct ListHead {
    /// Pointer to the first element. Be careful never to return a pointer to this to the user.
    first: ListElement,
}

/// Element in a list
pub struct ListElement {
    /// Pointer to the next element
    next: Option<NonNull<ListElement>>,
}

impl ListHead {
    /// Creates a new empty list
    #[must_use]
    pub const fn new() -> Self {
        Self {
            first: ListElement { next: None },
        }
    }

    /// Adds a new element as first element to the list.
    ///
    /// # Safety
    ///
    /// `element` must be a valid pointer for as long as it remains in the list, and not already be
    /// part of the list.
    #[inline]
    pub unsafe fn push(&mut self, element: NonNull<ListElement>) {
        // Safety: `element` is a valid pointer
        unsafe { (*element.as_ptr()).next = self.first.next };
        self.first.next = Some(element);
    }

    /// Removes the first element of the list
    #[inline]
    pub fn pop(&mut self) -> Option<NonNull<ListElement>> {
        let r = self.first.next;
        if let Some(first) = self.first.next {
            // Pop the first element. Safety: `first` is a valid pointer.
            self.first.next = unsafe { (*first.as_ptr()).next };
        }
        r
    }

    /// Returns the first element of the list
    #[must_use]
    #[inline]
    pub fn peek(&self) -> Option<NonNull<ListElement>> {
        self.first.next
    }

    /// Removes all elements from the list
    #[inline]
    pub fn clear(&mut self) {
        self.first.next = None;
    }

    /// Returns whether the list is empty
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.first.next.is_none()
    }

    /// Returns an iterator over the list
    #[must_use]
    #[inline]
    pub fn iter(&self) -> ListIter {
        ListIter {
            cur:     self.first.next,
            _marker: PhantomData,
        }
    }

    /// Applies a fallible function to each element, stopping at the first error
    pub fn try_for_each_mut<R: Try<Output = ()>>(
        &mut self,
        mut f: impl for<'a> FnMut(ListElementMut<'a>) -> R,
    ) -> R {
        // Start with first element
        let mut next = self.first.next;
        let mut prev = NonNull::from(&mut self.first);

        // Iterate over all elements
        while let Some(cur) = next {
            // Build list element
            let mut elem = ListElementMutInner { cur };

            // Invoke function, return on error
            f(ListElementMut {
                inner: &mut elem,
                prev,
            })?;

            // Take pointer to next and previous element from modified list element. Safety:
            // `elem.cur` is a valid pointer.
            unsafe {
                next = (*elem.cur.as_ptr()).next;
                prev = elem.cur;
            }
        }

        R::from_output(())
    }
}

/// Iterator over a list
pub struct ListIter<'a> {
    /// Current list element
    cur:     Option<NonNull<ListElement>>,
    /// Marker that uses the lifetime
    _marker: PhantomData<&'a ListElement>,
}

impl<'a> Iterator for ListIter<'a> {
    type Item = NonNull<ListElement>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let r = self.cur;
        if let Some(cur) = self.cur {
            // Move to the next element. Safety: `cur` is a valid pointer.
            self.cur = unsafe { (*cur.as_ptr()).next };
        }
        r
    }
}

/// Reference to a list element that allows modification of the list
pub struct ListElementMut<'a> {
    /// Reference to inner part
    inner: &'a mut ListElementMutInner,
    /// Previous list element (the one before `cur`). This may be the list head.
    prev:  NonNull<ListElement>,
}

/// Inner part of a [`ListElementMut`], which is not consumed when the element is removed
struct ListElementMutInner {
    /// Current list element, or the one before it if the current element was removed
    cur: NonNull<ListElement>,
}

impl<'a> ListElementMut<'a> {
    /// Returns the list element
    #[must_use]
    #[inline]
    pub fn get(&self) -> NonNull<ListElement> {
        self.inner.cur
    }

    /// Removes this element from the list and returns it
    #[inline]
    #[allow(clippy::must_use_candidate)]
    pub fn remove(self) -> NonNull<ListElement> {
        let cur = self.inner.cur;
        // Safety: `cur` and `prev` are valid pointers
        unsafe { (*self.prev.as_ptr()).next = (*cur.as_ptr()).next };
        self.inner.cur = self.prev;
        cur
    }

    /// Inserts a new element before this one.
    ///
    /// # Safety
    ///
    /// `element` must be a valid pointer for as long as it remains in the list, and not already be
    /// part of the list.
    #[inline]
    pub unsafe fn insert_before(&mut self, element: NonNull<ListElement>) {
        // Safety: `prev` and `element` are valid pointers
        unsafe {
            (*self.prev.as_ptr()).next = Some(element);
            (*element.as_ptr()).next = Some(self.inner.cur);
        }
        // Element before the current one changed
        self.prev = element;
    }

    /// Inserts a new element after this one.
    ///
    /// # Safety
    ///
    /// `element` must be a valid pointer for as long as it remains in the list, and not already be
    /// part of the list.
    #[inline]
    pub unsafe fn insert_after(&mut self, element: NonNull<ListElement>) {
        // Safety: `cur` and `element` are valid pointers
        unsafe {
            (*element.as_ptr()).next = (*self.inner.cur.as_ptr()).next;
            (*self.inner.cur.as_ptr()).next = Some(element);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::{boxed::Box, vec, vec::Vec};
    use core::{mem::MaybeUninit, ops::ControlFlow};

    use itertools::Itertools;

    use super::*;

    /// Allocates a new list element
    fn new_elem() -> NonNull<ListElement> {
        let elem = Box::leak(Box::new(MaybeUninit::uninit())).as_mut_ptr();
        // Safety: Pointer is not null
        unsafe { NonNull::new_unchecked(elem) }
    }

    /// Deletes a list element.
    ///
    /// # Safety
    ///
    /// Element must be valid.
    unsafe fn delete_elem(elem: NonNull<ListElement>) {
        // Safety: Element is valid
        unsafe { Box::from_raw(elem.as_ptr()) };
    }

    /// Creates a new list with the given size
    fn new_list(size: usize) -> (ListHead, Vec<NonNull<ListElement>>) {
        let mut list = ListHead::new();
        let mut vec = Vec::new();

        for _ in 0..size {
            let elem = new_elem();
            // Safety: Element is valid
            unsafe { list.push(elem) };
            vec.insert(0, elem);
        }

        assert!(equal(&list, &vec));
        (list, vec)
    }

    /// Deletes every list element
    fn delete_list(mut list: ListHead) {
        while let Some(elem) = list.pop() {
            // Safety: Element is valid
            unsafe { delete_elem(elem) };
        }
    }

    /// Checks if list and slice are equal
    fn equal(list: &ListHead, slice: &[NonNull<ListElement>]) -> bool {
        list.iter().eq(slice.iter().copied())
    }

    /// Tests `push`
    #[test]
    fn test_push() {
        for size in 0..=5 {
            // Create list and vector
            let (mut list, mut vec) = new_list(size);

            // Push element to both
            let elem = new_elem();
            // Safety: Element is valid
            unsafe { list.push(elem) };
            vec.insert(0, elem);

            // Assert equality
            assert!(equal(&list, &vec));
            delete_list(list);
        }
    }

    /// Tests `pop`
    #[test]
    fn test_pop() {
        for size in 0..=5 {
            // Create list and vector
            let (mut list, mut vec) = new_list(size);

            // Pop element from both
            let elem = list.pop();
            if let Some(elem) = elem {
                // Safety: Element is valid
                unsafe { delete_elem(elem) };
            }
            if !vec.is_empty() {
                vec.remove(0);
            }

            // Assert equality
            assert!(equal(&list, &vec));
            delete_list(list);
        }
    }

    /// Tests `peek`
    #[test]
    fn test_peek() {
        for size in 0..=5 {
            // Create list
            let (list, _) = new_list(size);

            // Peek returns the first element
            assert!(list.peek() == list.iter().next());
            delete_list(list);
        }
    }

    /// Tests `try_for_each_mut`
    #[test]
    fn test_try_for_each_mut() {
        for size in 0..=3 {
            for actions_size in 1..=size {
                let all_actions = vec![0..=13; actions_size]
                    .into_iter()
                    .multi_cartesian_product();
                for mut actions in all_actions {
                    // Create list
                    let (mut list, _) = new_list(size);

                    // Iterate and apply actions
                    list.try_for_each_mut(|mut elem| {
                        let action = actions.pop().unwrap();
                        let (op, del) = (action / 2, action % 2);

                        match op {
                            0 => {}
                            1 => {
                                // Safety: Element is valid
                                unsafe { elem.insert_before(new_elem()) };
                            }
                            2 => {
                                // Safety: Element is valid
                                unsafe { elem.insert_after(new_elem()) };
                            }
                            3 => {
                                // Safety: Element is valid
                                unsafe { elem.insert_before(new_elem()) };
                                // Safety: Element is valid
                                unsafe { elem.insert_before(new_elem()) };
                            }
                            4 => {
                                // Safety: Element is valid
                                unsafe { elem.insert_after(new_elem()) };
                                // Safety: Element is valid
                                unsafe { elem.insert_after(new_elem()) };
                            }
                            5 => {
                                // Safety: Element is valid
                                unsafe { elem.insert_before(new_elem()) };
                                // Safety: Element is valid
                                unsafe { elem.insert_after(new_elem()) };
                            }
                            6 => {
                                // Safety: Element is valid
                                unsafe { elem.insert_after(new_elem()) };
                                // Safety: Element is valid
                                unsafe { elem.insert_before(new_elem()) };
                            }
                            _ => {
                                unreachable!();
                            }
                        }

                        if del != 0 {
                            let e = elem.remove();
                            // Safety: Element is valid
                            unsafe { delete_elem(e) };
                        }

                        if actions.is_empty() {
                            ControlFlow::Break(())
                        } else {
                            ControlFlow::Continue(())
                        }
                    });

                    // Delete list
                    delete_list(list);
                }
            }
        }
    }

    /// Tests the basic functionality of the list
    #[test]
    fn test_linked_list() {
        // Create list
        let mut a: MaybeUninit<ListElement> = MaybeUninit::uninit();
        let mut b: MaybeUninit<ListElement> = MaybeUninit::uninit();
        let mut c: MaybeUninit<ListElement> = MaybeUninit::uninit();

        let a = NonNull::new(a.as_mut_ptr()).unwrap();
        let b = NonNull::new(b.as_mut_ptr()).unwrap();
        let c = NonNull::new(c.as_mut_ptr()).unwrap();

        let mut list = ListHead::new();
        // Safety: `a` and `b` are valid until the list is dropped
        unsafe {
            list.push(a);
            list.push(b);
        }

        // Remove `b` and insert `c`
        assert!(
            list.try_for_each_mut(|mut elem| {
                if elem.get() == b {
                    // Safety: `c` is valid until the list is dropped
                    unsafe { elem.insert_after(c) };
                    elem.remove();
                    ControlFlow::Break(123)
                } else {
                    ControlFlow::Continue(())
                }
            }) == ControlFlow::Break(123)
        );
        assert!(list.iter().collect::<Vec<_>>() == vec![c, a]);

        // Remove `c`
        assert!(list.pop() == Some(c));
        assert!(list.iter().collect::<Vec<_>>() == vec![a]);

        // Remove `a`
        assert!(list.pop() == Some(a));
        assert!(list.iter().collect::<Vec<_>>() == vec![]);

        // Ensure `pop` works on empty lists
        assert!(list.pop().is_none());
        assert!(list.iter().collect::<Vec<_>>() == vec![]);
        assert!(list.pop().is_none());
    }
}
