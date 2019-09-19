package project2task5;

public class User {
    // two invariants:
    // id: the identify number of the user
    // sum: the sum value of this user
    private String id;
    private double sum;
    
    // constructor
    public User(String id) {
        this.id = id;
        sum = 0;
    }
    
    // Add n to the sum of this user
    public void add(double n) {
        sum += n;
    }
    
    // Subtract n from the sum of this user
    public void subtract(double n) {
        sum -= n;
    }
    
    // view the sum of this user
    public double view() {
        return sum;
    }
}
