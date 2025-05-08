package ca.nrc.cadc.ac;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * A custom set built on a list implementation.
 * <p>
 * Ordering will not be deterministic as per the Set specification.
 */
public class UserSet implements Set<User> {

    private List<User> users;

    public UserSet() {
        users = new ArrayList<User>();
    }

    public User getUser(Principal identity) {
        User test = null;
        for (User u : users) {
            test = new User();
            test.getIdentities().add(identity);
            if (test.isConsistent(u)) {
                return u;
            }
        }
        return null;
    }

    public List<User> getUserList() {
        return users;
    }

    @Override
    public boolean add(User e) {
        if (!users.contains(e)) {
            users.add(e);
            return true;
        }
        return false;
    }

    @Override
    public boolean addAll(Collection<? extends User> c) {
        Iterator<? extends User> i = c.iterator();
        boolean modified = false;
        while (i.hasNext()) {
            if (this.add(i.next())) {
                modified = true;
            }
        }
        return modified;
    }

    @Override
    public void clear() {
        users.clear();
    }

    @Override
    public boolean contains(Object o) {
        return users.contains(o);
    }

    @Override
    public boolean containsAll(Collection<?> c) {
        return users.containsAll(c);
    }

    @Override
    public boolean isEmpty() {
        return users.isEmpty();
    }

    @Override
    public Iterator<User> iterator() {
        return users.iterator();
    }

    @Override
    public boolean remove(Object o) {
        if (users.contains(o)) {
            users.remove(o);
            return true;
        }
        return false;
    }

    @Override
    public boolean removeAll(Collection<?> c) {
        Iterator<?> i = c.iterator();
        boolean modified = false;
        while (i.hasNext()) {
            if (this.remove(i.next())) {
                modified = true;
            }
        }
        return modified;
    }

    @Override
    public boolean retainAll(Collection<?> c) {
        Iterator<User> i = users.listIterator();
        boolean modified = false;
        User next = null;
        while (i.hasNext()) {
            next = i.next();
            if (!c.contains(next)) {
                i.remove();
                modified = true;
            }
        }
        return modified;
    }

    @Override
    public int size() {
        return users.size();
    }

    @Override
    public Object[] toArray() {
        return users.toArray();
    }

    @Override
    public <T> T[] toArray(T[] a) {
        return users.toArray(a);
    }

}
