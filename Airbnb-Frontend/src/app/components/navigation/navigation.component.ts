import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { User } from 'src/app/models/user.model';
import { UserService } from 'src/app/services/user.service';

@Component({
  selector: 'app-navigation',
  templateUrl: './navigation.component.html',
  styleUrls: ['./navigation.component.css']
})

export class NavigationComponent {

  isLoggedIn(): boolean {

    if (localStorage.getItem("authToken") != null) {
      return true;
    }
    else {
      return false;
    }
  }
}
