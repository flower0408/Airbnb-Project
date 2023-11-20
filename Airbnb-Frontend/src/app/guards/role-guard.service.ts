import { Injectable } from '@angular/core';
import { Router, CanActivate, ActivatedRouteSnapshot, CanActivateFn, RouterStateSnapshot } from '@angular/router';
import { JwtHelperService } from '@auth0/angular-jwt';
import { Observable } from 'rxjs';

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

    console.log('Expected Roles:', expectedRoles);

    if (!token) {
      this.router.navigate(['']);
      return false;
    }

    const info = jwt.decodeToken(token);

    // Check if info.userType is defined and contains at least one element
    if (info && info.userType) {
      const roles: string[] = expectedRoles.split('|', 3);

      if (roles.indexOf(info.userType) === -1) {
        this.router.navigate(['/Main-Page']);
        return false;
      }
    } else {
      this.router.navigate(['']);
      return false;
    }

    return true;
  }
}
