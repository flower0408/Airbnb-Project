export class User {
    id: string = "";
    firstName: string = "";
    lastName: string = "";
    gender: string = "";
    age: number = 0;
    residence: string = "";
    username: string = "";
    password: string = "";
    email: string = "";
    userType: string = "";
    highlighted: boolean = false;

    User(id:string,firstName: string, lastName: string, gender: string, age: number, residence: string, username: string, password: string, email: string, userType: string, highlighted: boolean) {
        this.id = id;
        this.firstName = firstName;
        this.lastName = lastName;
        this.gender = gender;
        this.age = age;
        this.residence = residence;
        this.username = username;
        this.password = password;
        this.email = email;
        this.userType = userType;
        this.highlighted = highlighted;
    }
}
