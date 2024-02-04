import { Injectable } from '@angular/core';
import { Router, CanActivate, ActivatedRouteSnapshot, CanActivateFn, RouterStateSnapshot } from '@angular/router';
import { JwtHelperService } from '@auth0/angular-jwt';
import {Observable, of} from 'rxjs';
import {HttpResponse} from "@angular/common/http";

@Injectable({
  providedIn: 'root'
})
export class RoleGuardService implements CanActivate {

  constructor(
    public router: Router
  ) { }

  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): boolean | Observable<boolean> | Promise<boolean> {
    const expectedRoles: string = route.data['expectedRoles'];
    const token = localStorage.getItem('authToken');
    const jwt: JwtHelperService = new JwtHelperService();

    // Moze i ne mora da se prikazuje
    //console.log('Expected Roles:', expectedRoles);

    if (!token) {
      console.error('Access forbidden. Invalid token or missing user type.');
      this.router.navigate(['']);
      return false;
    }

    const info = jwt.decodeToken(token);

    // Check if info.userType is defined and contains at least one element
    if (info && info.userType) {
      const roles: string[] = expectedRoles.split('|', 3);

      if (roles.indexOf(info.userType) === -1) {
        console.error('Access forbidden. User does not have the required role.');
        this.router.navigate(['']);
        return of(false);
      }
    } else {
      console.error('Access forbidden. Invalid token or missing user type.');
      this.router.navigate(['']);
      return of(false);
    }

    return of(true);
  }
}
