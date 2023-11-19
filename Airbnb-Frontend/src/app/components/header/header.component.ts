import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { User } from 'src/app/models/user.model';
import { UserService } from 'src/app/services/user.service';

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.css']
})
export class HeaderComponent implements OnInit {

  loggedUser!:User;

  constructor(private router: Router,private userService:UserService) { }

  ngOnInit(): void {
    this.userService.getUser().subscribe(
      (user: User) => {
        this.loggedUser = user;
      },
      (error) => {
        console.error('Error get user data:', error);
      }
    );
  }

  isLoggedIn(): boolean {
    
    if (localStorage.getItem("authToken") != null) {
      return true;
    }
    else {
      return false;
    }
  }


  logout() {
    localStorage.clear();
    this.router.navigate(['']);
  }

}
