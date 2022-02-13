// Classes

/**
 * The type of an error thrown by this library because of a failed approval.
 */
export class Denial extends Error {
    cause: string
    value?: string | boolean

    constructor(cause: string, value?: any) {
        super(value !== undefined ? `Denial: ${cause}: ${value}` : `Denial: ${cause}`);
        this.cause = cause
        this.value = value
    }
}

// Types

/**
 * A type representing the approval results.
 */
export type Approval = {
    /**
     * True, if the access is approved. False, otherwise.
     */
    value: boolean,
    /**
     * The error that caused the approval to fail.
     */
    error?: any
}

/**
 * An object containing a permission to be checked in another context.
 */
export type Continuation<T> = {
    /**
     * The type of the continuation.
     * Used to assert the type of the permission's parameter.
     */
    type: string,
    /**
     * The permission to continue the role with.
     */
    permission: Permission<T>
}

/**
 * A type representing a permission signature that can be verified.
 */
export type Role = {
    /**
     * The value of this role.
     * A string if the role can be verified directly.
     * Or a continuation to be verified on a specific context.
     * If the reciever of this role does not support the type
     * of the continuation, it is totally free to throw whatever
     * exception it want. Since it is the resposibility of the
     * continuation creator to make sure the continuation is
     * supported by the role verifier (aka, the privilege object).
     */
    value: string | Continuation<any>
    /**
     * The error to report when this role is not verified.
     */
    error?: any
}

// Privilege

/**
 * The types of the results of a privilege evaluation.
 */
export type PrivilegeResult = boolean | Approval | Privilege[]
/**
 * The types of a privilege output.
 */
export type PrivilegePromise = Promise<PrivilegeResult> | PrivilegeResult
/**
 * The type of a privilege function.
 */
export type PrivilegeFunction = { (role: Role): PrivilegePromise }
/**
 * The types of a privilege.
 */
export type Privilege = PrivilegePromise | PrivilegeFunction
/*
 boolean     : PrivilegeResult : PrivilegePromise : Privilege
 Approval    : PrivilegeResult : PrivilegePromise : Privilege
 Privilege[] : PrivilegeResult : PrivilegePromise : Privilege
 Promise<PrivilegeResult>      : PrivilegePromise : Privilege
 PrivilegeFunction                                : Privilege
 Constructors
*/

// Permit

/**
 * The types of the results of a permit evaluation.
 */
export type PermitResult<T> = string | Role | Permit<T>[]
/**
 * The types of a permit output.
 */
export type PermitOutput<T> = Promise<PermitResult<T>> | PermitResult<T>
/**
 * The type of a permit function.
 */
export type PermitFunction<T> = { (target: T): PermitOutput<T> }
/**
 * The types of a permit.
 */
export type Permit<T> = PermitOutput<T> | PermitFunction<T>
/*
 string   : PermitResult : PermitPromise : Permit
 Result   : PermitResult : PermitPromise : Permit
 Permit[] : PermitResult : PermitPromise : Permit
 Promise<PermitResult>   : PermitPromise : Permit
 PermitFunction                          : Permit
*/

// Permission

/**
 * The types of the results of a permission evaluation.
 */
export type PermissionResult<T> = boolean | Approval | Permission<T>[]
/**
 * The types of a permission output.
 */
export type PermissionPromise<T> = Promise<PermissionResult<T>> | PermissionResult<T>
/**
 * The type of a permission function.
 */
export type PermissionFunction<T> = { (privilege: Privilege, target: T): PermissionPromise<T> }
/**
 * The types of a permission.
 */
export type Permission<T> = PermissionPromise<T> | PermissionFunction<T>
/*
 boolean      : PermissionResult : PermissionPromise : Permission
 Approval     : PermissionResult : PermissionPromise : Permission
 Permission[] : PermissionResult : PermissionPromise : Permission
 Promise<PermissionResult>       : PermissionPromise : Permission
 PermissionFunction                                  : Permission
*/

// Utils

/**
 * Permission utilities.
 */
export namespace Permission {
    /**
     * Create a permission that returns the result of checking the given permit.
     */
    export const create = <T>(permit: Permit<T>): Permission<T> => {
        return (privilege, target) => checkPermit(permit, privilege, target)
    }

    /**
     * Create a new permission that returns the result of invoking the given
     * permission with the target being the result of invoking the given mapper
     * with the target given to it.
     */
    export const map = <T, U>(permission: Permission<T>, mapper: { (target: U): T | Promise<T> }): Permission<U> => {
        return async (privilege, target) => evaluatePermission(permission, privilege, await mapper(target))
    }

    /**
     * Create a new permission that always validates a continuation role that has the given type, permission and error.
     */
    export const continuation = <T>(type: string, permission: Permission<T>, error?: any): Permission<any> => {
        return (privilege, target) => checkPermit({value: {type, permission}, error}, privilege, target)
    }
}

/**
 * Permit utilities.
 */
export namespace Permit {
    /**
     * Create a permit that returns the result of invoking the given permit with
     * the target being the result of invoking the given mapper with the target given to it.
     */
    export const map = <T, U>(permit: Permit<T>, mapper: { (target: U): T | Promise<T> }): Permit<U> => {
        return async (target) => evaluatePermit(permit, await mapper(target))
    }
}

/**
 * Role utilities.
 */
export namespace Role {
    /**
     * Create a new continuation role with the given parameters.
     */
    export const continuation = <T>(type: string, permission: Permission<T>, error?: any): Role => {
        return {
            value: {type, permission},
            error
        }
    }
}

// Validators

/**
 * Check the given permit.
 *
 * @param permit the permit to be checked.
 * @param privilege the privilege.
 * @param target the target to check the permit for.
 * @return an approval object.
 */
export const checkPermit = async <T>(permit: Permit<T>, privilege: Privilege, target?: T): Promise<Approval> => {
    for (const role of await evaluatePermit(permit, target)) {
        const approvals = await evaluatePrivilege(privilege, role)

        if (approvals.length === 0)
            return {value: false, error: role.error}

        for (const approval of approvals)
            if (!approval.value)
                return approval
    }

    return {value: true}
}

/**
 * Check the given permission.
 *
 * @param permission the permission to be checked.
 * @param privilege the privilege.
 * @param target the target to check the permission for.
 * @return an approval object.
 */
export const checkPermission = async <T>(permission: Permission<T>, privilege: Privilege, target?: T): Promise<Approval> => {
    const approvals = await evaluatePermission(permission, privilege, target)

    if (approvals.length === 0)
        return {value: false, error: new Denial('Approval')}

    for (const approval of approvals)
        if (!approval.value)
            return approval

    return {value: true}
}

// Is

/**
 * Check the given permit.
 *
 * @param permit the permit to be checked.
 * @param privilege the privilege.
 * @param target the target to check the permit for.
 * @return true, if the privilege is permitted the given permit for the given target.
 */
export const isPermitted = async <T>(permit: Permit<T>, privilege: Privilege, target?: T): Promise<boolean> => {
    return await checkPermit(permit, privilege, target).then(it => it.value)
}

/**
 * Check the given permission.
 *
 * @param permit the permission to be checked.
 * @param privilege the privilege.
 * @param target the target to check the permit for.
 * @return true, if the privilege is permissioned the given permission for the given target.
 */
export const isPermissioned = async <T>(permission: Permission<T>, privilege: Privilege, target?: T): Promise<boolean> => {
    return await checkPermission(permission, privilege, target).then(it => it.value)
}

// Require

/**
 * Check the given permit and throw the error if it fails.
 *
 * @param permit the permit to be checked.
 * @param privilege the privilege.
 * @param target the target to check the permit for.
 */
export const requirePermit = async <T>(permit: Permit<T>, privilege: Privilege, target?: T): Promise<T> => {
    const approval = await checkPermit(permit, privilege, target)

    if (!approval.value)
        switch (typeof approval.error) {
            case 'string':
            case 'boolean':
            case 'undefined':
            case 'bigint':
            case 'number':
            case 'undefined':
                throw new Denial('Permit', approval.error)
            default:
                throw approval.error
        }

    return target!
}

/**
 * Check the given permission and throw the error if it fails.
 *
 * @param permission the permission to be checked.
 * @param privilege the privilege.
 * @param target the target to check the permission for.
 */
export const requirePermission = async <T>(permission: Permission<T>, privilege: Privilege, target?: T): Promise<T> => {
    const approval = await checkPermission(permission, privilege, target)

    if (!approval.value)
        switch (typeof approval.error) {
            case 'string':
            case 'boolean':
            case 'undefined':
            case 'bigint':
            case 'number':
            case 'undefined':
                throw new Denial('Permission', approval.error)
            default:
                throw approval.error
        }

    return target!
}

// Evaluations

/**
 * Evaluate the given permission.
 *
 * @param permission the permission to be evaluated.
 * @param privilege the privilege
 * @param target the target to evaluate the permission for.
 * @return the approval objects.
 */
export const evaluatePermission = async <T>(permission: Permission<T>, privilege: Privilege, target?: T): Promise<Approval[]> => {
    // Promise<PermissionResult>
    if (permission instanceof Promise)
        return evaluatePermission(await permission, privilege, target)

    // Permission[]
    if (Array.isArray(permission))
        return Promise
            .all(permission.map(it => evaluatePermission(it, privilege, target)))
            .then(it => it.flatMap(it => it))

    // boolean
    if (typeof permission === 'boolean')
        return [{value: permission, error: new Denial('Permission', permission)}]

    // Approval
    if (typeof permission === 'object') {
        return [permission]
    }

    // PermissionFunction
    if (typeof permission === 'function')
        return evaluatePermission(await permission(privilege, target!), privilege, target)

    throw new Error('Invalid Permission Type')
}

/**
 * Evaluate the given privilege.
 *
 * @param privilege the privilege to be evaluated.
 * @param role the role to evaluate the privilege with.
 * @return the approval objects.
 */
export const evaluatePrivilege = async (privilege: Privilege, role: Role): Promise<Approval[]> => {
    // Promise<PrivilegeResult>
    if (privilege instanceof Promise)
        return evaluatePrivilege(await privilege, role)

    // Privilege[]
    if (Array.isArray(privilege))
        return Promise
            .all(privilege.map(it => evaluatePrivilege(it, role)))
            .then(it => it.flatMap(it => it))

    // boolean
    if (typeof privilege === 'boolean')
        return [{value: privilege, error: new Denial('Privilege', privilege)}]

    // Approval
    if (typeof privilege === 'object')
        return [privilege]

    // PrivilegeFunction
    if (typeof privilege === 'function')
        return evaluatePrivilege(await privilege(role), role)

    throw new Error('Invalid Privilege Type')
}

/**
 * Evaluate the given permits
 *
 * @param permit the permit to be evaluated.
 * @param target the target to evaluate the permit for.
 * @return the roles to test when checking the permit.
 */
export const evaluatePermit = async <T>(permit: Permit<T>, target?: T): Promise<Role[]> => {
    // Promise<PermitResult>
    if (permit instanceof Promise)
        return evaluatePermit(await permit, target)

    // Permit[]
    if (Array.isArray(permit))
        return Promise
            .all(permit.map(it => evaluatePermit(it, target)))
            .then(it => it.flatMap(it => it))

    // string
    if (typeof permit === 'string')
        return [{value: permit, error: new Denial('Permit', permit)}]

    // Result
    if (typeof permit === 'object')
        return [permit]

    // PermitFunction
    if (typeof permit === 'function')
        return evaluatePermit(await permit(target!), target)

    throw new Error('Invalid Permit Type')
}
